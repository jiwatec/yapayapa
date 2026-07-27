//! Authenticated WebSocket relay. The server forwards opaque sealed
//! envelopes; it can never decrypt them. Delivery is at-least-once with
//! client-side idempotency on `message_id`, and the server-side queue is
//! marked acked exactly once.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use uuid::Uuid;
use yapayapa_common::types::{ClientFrame, DeliveryState, ServerFrame, WireMessage};
use yapayapa_common::validate::MAX_WS_FRAME_BYTES;

use crate::auth::AuthUser;
use crate::state::{AppState, OnlineConn, RateKey};
use crate::store::{MessageState, QueuedMessage};

pub async fn ws_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    ws: WebSocketUpgrade,
) -> Response {
    let user_id = auth.user_id;
    ws.max_message_size(MAX_WS_FRAME_BYTES)
        .on_upgrade(move |socket| handle_socket(state, user_id, socket))
}

async fn handle_socket(state: Arc<AppState>, user_id: Uuid, socket: WebSocket) {
    let conn_id = Uuid::new_v4();
    let (tx, mut rx) = mpsc::unbounded_channel::<ServerFrame>();
    state.online.lock().unwrap().insert(
        user_id,
        OnlineConn {
            conn_id,
            tx: tx.clone(),
        },
    );
    tracing::info!(%user_id, %conn_id, "websocket connected");

    let (mut sink, mut stream) = socket.split();
    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            let Ok(json) = serde_json::to_string(&frame) else {
                continue;
            };
            if sink.send(Message::Text(json.into())).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    // Drain the offline queue and any delivery receipts that accumulated
    // while this user was away.
    if let Err(e) = drain_backlog(&state, user_id, &tx).await {
        tracing::warn!(%user_id, error = %e, "failed to drain backlog");
    }

    while let Some(Ok(msg)) = stream.next().await {
        let text = match msg {
            Message::Text(t) => t,
            Message::Close(_) => break,
            _ => continue,
        };
        if text.len() > MAX_WS_FRAME_BYTES {
            let _ = tx.send(ServerFrame::Error {
                message_id: None,
                error: "frame too large".into(),
            });
            continue;
        }
        let frame: ClientFrame = match serde_json::from_str(&text) {
            Ok(f) => f,
            Err(_) => {
                let _ = tx.send(ServerFrame::Error {
                    message_id: None,
                    error: "malformed frame".into(),
                });
                continue;
            }
        };
        match frame {
            ClientFrame::Ping => {
                let _ = tx.send(ServerFrame::Pong);
            }
            ClientFrame::Send { message } => {
                if let Err(err) = handle_send(&state, user_id, &message).await {
                    let _ = tx.send(ServerFrame::Error {
                        message_id: Some(message.message_id),
                        error: err,
                    });
                } else {
                    let _ = tx.send(ServerFrame::Accepted {
                        message_id: message.message_id,
                    });
                }
            }
            ClientFrame::Ack { message_id } => {
                if let Err(e) = handle_ack(&state, user_id, message_id).await {
                    tracing::warn!(%user_id, %message_id, error = %e, "ack failed");
                }
            }
            ClientFrame::ReceiptAck { message_ids } => {
                if let Err(e) = state
                    .store
                    .mark_receipts_notified(user_id, &message_ids)
                    .await
                {
                    tracing::warn!(%user_id, error = %e, "receipt ack failed");
                }
            }
        }
    }

    // Only remove the map entry if it still belongs to this connection; a
    // reconnect may already have replaced it.
    {
        let mut online = state.online.lock().unwrap();
        if online.get(&user_id).is_some_and(|c| c.conn_id == conn_id) {
            online.remove(&user_id);
        }
    }
    writer.abort();
    tracing::info!(%user_id, %conn_id, "websocket disconnected");
}

async fn drain_backlog(
    state: &AppState,
    user_id: Uuid,
    tx: &mpsc::UnboundedSender<ServerFrame>,
) -> Result<(), crate::store::StoreError> {
    for queued in state.store.pending_messages(user_id).await? {
        if let Some(message) = queued_to_wire(&queued) {
            let _ = tx.send(ServerFrame::Deliver { message });
        }
    }
    // Receipts stay "unnotified" until the client durably records them and
    // replies with ReceiptAck — queuing a frame into a channel is not
    // delivery, and a client that disconnects mid-drain must see them again.
    for (message_id, s) in state.store.unnotified_receipts(user_id).await? {
        let _ = tx.send(ServerFrame::Receipt {
            message_id,
            state: match s {
                MessageState::SentToRelay => DeliveryState::SentToRelay,
                MessageState::Delivered => DeliveryState::Delivered,
                MessageState::Read => DeliveryState::Read,
            },
        });
    }
    Ok(())
}

fn queued_to_wire(q: &QueuedMessage) -> Option<WireMessage> {
    let envelope = serde_json::from_str(&q.envelope_json).ok()?;
    Some(WireMessage {
        message_id: q.message_id,
        sender_id: q.sender_id,
        recipient_id: q.recipient_id,
        group_id: q.group_id,
        sent_at: q.sent_at,
        envelope,
    })
}

async fn handle_send(state: &AppState, user_id: Uuid, msg: &WireMessage) -> Result<(), String> {
    if !state.rate_allow(RateKey::UserSend(user_id), 240, Duration::from_secs(10)) {
        return Err("rate limit exceeded".into());
    }
    if msg.sender_id != user_id {
        return Err("sender_id must be the authenticated user".into());
    }
    if msg.recipient_id == user_id {
        return Err("cannot send to yourself".into());
    }
    let recipient = state
        .store
        .user_by_id(msg.recipient_id)
        .await
        .map_err(|_| "internal error".to_string())?;
    if recipient.is_none() {
        return Err("recipient not found".into());
    }
    if let Some(group_id) = msg.group_id {
        // Group fan-out is pairwise: both parties must be members.
        let store = &state.store;
        let sender_role = store
            .member_role(group_id, user_id)
            .await
            .map_err(|_| "internal error".to_string())?;
        let recipient_role = store
            .member_role(group_id, msg.recipient_id)
            .await
            .map_err(|_| "internal error".to_string())?;
        if sender_role.is_none() || recipient_role.is_none() {
            return Err("sender and recipient must both be group members".into());
        }
    }
    let envelope_json =
        serde_json::to_string(&msg.envelope).map_err(|_| "malformed envelope".to_string())?;
    if envelope_json.len() > MAX_WS_FRAME_BYTES {
        return Err("envelope too large".into());
    }
    let queued = QueuedMessage {
        message_id: msg.message_id,
        sender_id: msg.sender_id,
        recipient_id: msg.recipient_id,
        group_id: msg.group_id,
        envelope_json,
        sent_at: msg.sent_at,
    };
    let newly_queued = state
        .store
        .enqueue_message(&queued)
        .await
        .map_err(|_| "internal error".to_string())?;
    if newly_queued {
        state
            .store
            .upsert_status(msg.message_id, user_id, MessageState::SentToRelay, true)
            .await
            .map_err(|_| "internal error".to_string())?;
        state.send_if_online(
            msg.recipient_id,
            ServerFrame::Deliver {
                message: msg.clone(),
            },
        );
    }
    Ok(())
}

async fn handle_ack(
    state: &AppState,
    user_id: Uuid,
    message_id: Uuid,
) -> Result<(), crate::store::StoreError> {
    // Only the recipient of the queued message can ack it; ack_message
    // enforces that and is idempotent (returns None on repeats).
    let Some(sender_id) = state.store.ack_message(message_id, user_id).await? else {
        return Ok(());
    };
    // Store first (unnotified), then push a live receipt if the sender is
    // online. The receipt stays re-deliverable until the sender confirms it
    // with ReceiptAck, so a crash between "queued to channel" and "client
    // persisted it" cannot lose it.
    state
        .store
        .upsert_status(message_id, sender_id, MessageState::Delivered, false)
        .await?;
    state.send_if_online(
        sender_id,
        ServerFrame::Receipt {
            message_id,
            state: DeliveryState::Delivered,
        },
    );
    Ok(())
}

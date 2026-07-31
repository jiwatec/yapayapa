//! Core messaging logic shared by the CLI chat, the TUI, outbox retry, and
//! background sync: composing (encrypt → local history → outbox), incoming
//! handling (verify → decrypt → dedupe → ack), and outbox flushing.

use chrono::Utc;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use uuid::Uuid;
use yapayapa_common::crypto::{open, seal, PublicIdentity, SealedEnvelope, SymmetricKey};
use yapayapa_common::types::{ChatContent, ClientFrame, GroupBody, ServerFrame, WireMessage};

use crate::session::Session;
use crate::store::{Contact, LocalState, OutboxEntry};

pub type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
pub type WsSink = SplitSink<WsStream, WsMessage>;
pub type WsSource = SplitStream<WsStream>;

/// Connect the authenticated WebSocket. Returns `None` when offline.
pub async fn connect_ws(session: &Session) -> Option<WsStream> {
    match tokio_tungstenite::connect_async(session.ws_url_with_token()).await {
        Ok((stream, _)) => Some(stream),
        Err(_) => None,
    }
}

pub async fn send_frame(sink: &mut WsSink, frame: &ClientFrame) -> anyhow::Result<()> {
    sink.send(WsMessage::Text(serde_json::to_string(frame)?.into()))
        .await?;
    Ok(())
}

/// Compose a direct message: store plaintext (encrypted) in local history as
/// queued_local, seal the envelope, and persist it to the outbox. Returns the
/// wire message ready to transmit.
pub fn compose_direct(
    session: &Session,
    recipient: &Contact,
    content: &ChatContent,
) -> anyhow::Result<WireMessage> {
    let message_id = Uuid::new_v4();
    let sent_at = Utc::now();
    let chat_id = recipient.user_id.to_string();
    session.store.insert_message(
        message_id,
        &chat_id,
        session.keystore.profile.user_id,
        "out",
        sent_at,
        LocalState::QueuedLocal,
        content,
    )?;
    let wire = seal_wire(
        session,
        message_id,
        recipient.user_id,
        &recipient.identity,
        None,
        content,
        sent_at,
    )?;
    Ok(wire)
}

/// Seal `content` to one recipient and persist the ciphertext to the outbox.
#[allow(clippy::too_many_arguments)]
pub fn seal_wire(
    session: &Session,
    message_id: Uuid,
    recipient_id: Uuid,
    recipient_identity: &PublicIdentity,
    group_id: Option<Uuid>,
    content: &ChatContent,
    sent_at: chrono::DateTime<Utc>,
) -> anyhow::Result<WireMessage> {
    recipient_identity
        .verify_prekey()
        .map_err(|_| anyhow::anyhow!("recipient identity failed verification"))?;
    let plaintext = serde_json::to_vec(content)?;
    let envelope: SealedEnvelope = seal(&session.keystore.identity, recipient_identity, &plaintext)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;
    let wire = WireMessage {
        message_id,
        sender_id: session.keystore.profile.user_id,
        recipient_id,
        group_id,
        sent_at,
        envelope,
    };
    session.store.outbox_add(&OutboxEntry {
        message_id,
        recipient_id,
        group_id,
        envelope_json: serde_json::to_string(&wire.envelope)?,
        sent_at,
    })?;
    Ok(wire)
}

/// Encrypt a group message body with the group key and wrap it as
/// `GroupCiphertext` content (which is then sealed pairwise per member).
pub fn group_ciphertext(
    session: &Session,
    group_id: Uuid,
    epoch: i64,
    key: &SymmetricKey,
    inner: &ChatContent,
) -> anyhow::Result<ChatContent> {
    let body = GroupBody {
        sender_username: session.keystore.profile.username.clone(),
        sent_at: Utc::now(),
        content: Box::new(inner.clone()),
    };
    let aad = format!("group-msg:{group_id}:{epoch}");
    let ct = key
        .encrypt(&serde_json::to_vec(&body)?, aad.as_bytes())
        .map_err(|e| anyhow::anyhow!("group encryption failed: {e}"))?;
    Ok(ChatContent::GroupCiphertext {
        group_id,
        epoch,
        ct: yapayapa_common::crypto::b64(&ct),
    })
}

/// What an incoming envelope turned into after decryption.
pub enum Incoming {
    /// A new message stored in `chat_id`; `line` is a printable rendering.
    Stored { chat_id: String, line: String },
    /// A group key was installed (no visible message).
    GroupKeyInstalled,
    /// Duplicate of a message we already stored (still needs an ack).
    Duplicate,
}

/// Verify, decrypt, and store an incoming wire message. The caller must ack
/// on `Ok`. Fails closed: any verification or decryption error is an `Err`
/// and the message is NOT acked (so it can be retried/inspected).
pub async fn handle_incoming(session: &Session, wire: &WireMessage) -> anyhow::Result<Incoming> {
    // Resolve the sender's pinned identity: local contact first, otherwise
    // fetch from the server (TOFU) if reachable.
    let sender = match session.store.contact_by_id(wire.sender_id)? {
        Some(c) => c,
        None => {
            let user = session
                .api
                .lookup(&wire.sender_id.to_string())
                .await
                .map_err(|e| anyhow::anyhow!("unknown sender and lookup failed: {e}"))?;
            user.identity
                .verify_prekey()
                .map_err(|_| anyhow::anyhow!("sender identity failed verification"))?;
            session.store.upsert_contact(&user, false)?;
            session
                .store
                .contact_by_id(wire.sender_id)?
                .ok_or_else(|| anyhow::anyhow!("contact vanished"))?
        }
    };

    let plaintext = open(&session.keystore.identity, &sender.identity, &wire.envelope)
        .map_err(|e| anyhow::anyhow!("could not decrypt message from {}: {e}", sender.username))?;
    let content: ChatContent = serde_json::from_slice(&plaintext)?;

    match content {
        ChatContent::GroupKey {
            group_id,
            epoch,
            key,
        } => {
            let key_bytes = yapayapa_common::crypto::b64_arr::<32>(&key)
                .ok_or_else(|| anyhow::anyhow!("malformed group key"))?;
            // Only accept a group key if the sender is actually a member (we
            // check when online; offline-installed keys still require the
            // sealed envelope from a pinned sender identity).
            session
                .store
                .store_group_key(group_id, epoch, &SymmetricKey(key_bytes))?;
            // Pull full membership when online so the group is immediately
            // usable — members cached and identities pinned — not just named.
            // Without this the group appears but shows "no other members yet"
            // until a manual `groups info`. Best-effort: a single unverifiable
            // member (cache_group logs and returns Err) or being offline still
            // leaves the key installed and a bare group row present.
            match session.api.group_info(group_id).await {
                Ok(info) => {
                    // cache_group upserts the group first, so even a partial
                    // failure leaves it named and listed.
                    if let Err(e) = crate::groups::cache_group(session, &info) {
                        tracing::warn!(%group_id, error = %e, "group membership sync incomplete");
                    }
                }
                Err(_) if session.store.group_name(group_id)?.is_none() => {
                    session
                        .store
                        .upsert_group(group_id, &format!("group {group_id}"), epoch)?;
                }
                Err(_) => {}
            }
            Ok(Incoming::GroupKeyInstalled)
        }
        ChatContent::GroupCiphertext {
            group_id,
            epoch,
            ct,
        } => {
            let Some(key) = session.store.group_key(group_id, epoch)? else {
                anyhow::bail!(
                    "no key for group {group_id} epoch {epoch} yet — the key message may still be in flight"
                );
            };
            let ct = yapayapa_common::crypto::b64_vec(&ct)
                .ok_or_else(|| anyhow::anyhow!("malformed group ciphertext"))?;
            let aad = format!("group-msg:{group_id}:{epoch}");
            let body_plain = key
                .decrypt(&ct, aad.as_bytes())
                .map_err(|_| anyhow::anyhow!("group message failed to decrypt"))?;
            let body: GroupBody = serde_json::from_slice(&body_plain)?;
            let stored_content = match body.content.as_ref() {
                ChatContent::Image { attachment_id, .. } => {
                    store_image_meta(session, wire.message_id, body.content.as_ref())?;
                    let _ = attachment_id;
                    (*body.content).clone()
                }
                other => other.clone(),
            };
            let chat_id = group_id.to_string();
            let new = session.store.insert_message(
                wire.message_id,
                &chat_id,
                wire.sender_id,
                "in",
                body.sent_at,
                LocalState::Delivered,
                &stored_content,
            )?;
            if !new {
                return Ok(Incoming::Duplicate);
            }
            let line = format!(
                "[{}] {}: {}",
                body.sent_at.format("%H:%M"),
                body.sender_username,
                render_content(&stored_content)
            );
            Ok(Incoming::Stored { chat_id, line })
        }
        content @ (ChatContent::Text { .. } | ChatContent::Image { .. }) => {
            if let ChatContent::Image { .. } = &content {
                store_image_meta(session, wire.message_id, &content)?;
            }
            let chat_id = sender.user_id.to_string();
            let new = session.store.insert_message(
                wire.message_id,
                &chat_id,
                wire.sender_id,
                "in",
                wire.sent_at,
                LocalState::Delivered,
                &content,
            )?;
            if !new {
                return Ok(Incoming::Duplicate);
            }
            let line = format!(
                "[{}] {}: {}",
                wire.sent_at.format("%H:%M"),
                sender.username,
                render_content(&content)
            );
            Ok(Incoming::Stored { chat_id, line })
        }
    }
}

fn store_image_meta(
    session: &Session,
    message_id: Uuid,
    content: &ChatContent,
) -> anyhow::Result<()> {
    if let ChatContent::Image {
        attachment_id,
        key,
        filename,
        mime,
        size,
        plaintext_hash,
    } = content
    {
        session.store.store_attachment(
            message_id,
            &crate::store::AttachmentInfo {
                attachment_id: *attachment_id,
                key_b64: key.clone(),
                filename: filename.clone(),
                mime: mime.clone(),
                size: *size,
                plaintext_hash: plaintext_hash.clone(),
            },
        )?;
    }
    Ok(())
}

/// Record attachment metadata for a message we sent (so we can re-download
/// and open our own images later).
pub fn store_outgoing_attachment(
    session: &Session,
    message_id: Uuid,
    content: &ChatContent,
) -> anyhow::Result<()> {
    if let ChatContent::Image {
        attachment_id,
        key,
        filename,
        mime,
        size,
        plaintext_hash,
    } = content
    {
        session.store.store_attachment(
            message_id,
            &crate::store::AttachmentInfo {
                attachment_id: *attachment_id,
                key_b64: key.clone(),
                filename: filename.clone(),
                mime: mime.clone(),
                size: *size,
                plaintext_hash: plaintext_hash.clone(),
            },
        )?;
    }
    Ok(())
}

pub fn render_content(content: &ChatContent) -> String {
    match content {
        ChatContent::Text { body } => body.clone(),
        ChatContent::Image {
            attachment_id,
            filename,
            size,
            ..
        } => format!(
            "[image: {filename}, {} KiB — download with `yapayapa attachments download {attachment_id}`]",
            size / 1024
        ),
        ChatContent::GroupKey { group_id, epoch, .. } => {
            format!("[group key update for {group_id} epoch {epoch}]")
        }
        ChatContent::GroupCiphertext { group_id, .. } => {
            format!("[encrypted group message for {group_id}]")
        }
    }
}

/// Push every outbox entry over an open sink. Entries are only removed when
/// the relay confirms with `Accepted` (see `handle_server_frame`).
pub async fn flush_outbox(session: &Session, sink: &mut WsSink) -> anyhow::Result<usize> {
    let entries = session.store.outbox_list()?;
    let n = entries.len();
    for e in entries {
        let envelope: SealedEnvelope = serde_json::from_str(&e.envelope_json)?;
        let wire = WireMessage {
            message_id: e.message_id,
            sender_id: session.keystore.profile.user_id,
            recipient_id: e.recipient_id,
            group_id: e.group_id,
            sent_at: e.sent_at,
            envelope,
        };
        send_frame(sink, &ClientFrame::Send { message: wire }).await?;
    }
    Ok(n)
}

/// Uniform processing of one server frame. Returns a printable event line
/// when something user-visible happened.
pub async fn handle_server_frame(
    session: &Session,
    sink: &mut WsSink,
    frame: ServerFrame,
) -> anyhow::Result<Option<(String, String)>> {
    match frame {
        ServerFrame::Deliver { message } => match handle_incoming(session, &message).await {
            Ok(Incoming::Stored { chat_id, line }) => {
                send_frame(
                    sink,
                    &ClientFrame::Ack {
                        message_id: message.message_id,
                    },
                )
                .await?;
                Ok(Some((chat_id, line)))
            }
            Ok(Incoming::GroupKeyInstalled) | Ok(Incoming::Duplicate) => {
                send_frame(
                    sink,
                    &ClientFrame::Ack {
                        message_id: message.message_id,
                    },
                )
                .await?;
                Ok(None)
            }
            Err(e) => {
                // Do not ack what we could not decrypt; it stays queued.
                tracing::warn!(error = %e, "failed to process incoming message");
                Ok(None)
            }
        },
        ServerFrame::Accepted { message_id } => {
            session.store.set_state(message_id, LocalState::Sent)?;
            session.store.outbox_remove(message_id)?;
            Ok(None)
        }
        ServerFrame::Receipt { message_id, .. } => {
            // Persist first, then confirm so the server stops re-sending.
            session.store.set_state(message_id, LocalState::Delivered)?;
            send_frame(
                sink,
                &ClientFrame::ReceiptAck {
                    message_ids: vec![message_id],
                },
            )
            .await?;
            Ok(None)
        }
        ServerFrame::Error { message_id, error } => Ok(Some((
            String::new(),
            match message_id {
                Some(id) => format!("! server rejected message {id}: {error}"),
                None => format!("! server error: {error}"),
            },
        ))),
        ServerFrame::Pong => Ok(None),
    }
}

/// Parse a raw websocket message into a server frame, if it is one.
pub fn parse_server_frame(msg: &WsMessage) -> Option<ServerFrame> {
    match msg {
        WsMessage::Text(t) => serde_json::from_str(t).ok(),
        _ => None,
    }
}

/// Short-lived sync: connect, flush the outbox, and process incoming frames
/// until the line goes quiet. Used by `outbox retry` and `status`, and after
/// offline composition. Returns (flushed, received) counts.
pub async fn sync_once(session: &Session) -> anyhow::Result<(usize, usize)> {
    let Some(ws) = connect_ws(session).await else {
        return Err(anyhow::anyhow!(
            "offline: cannot reach {}",
            session.config.server
        ));
    };
    let (mut sink, mut source) = ws.split();
    let flushed = flush_outbox(session, &mut sink).await?;
    let mut received = 0usize;
    // Read until 700 ms of silence — long enough for the relay to push the
    // backlog and confirmations, short enough for a snappy CLI.
    loop {
        match tokio::time::timeout(std::time::Duration::from_millis(700), source.next()).await {
            Ok(Some(Ok(msg))) => {
                if let Some(frame) = parse_server_frame(&msg) {
                    let is_deliver = matches!(frame, ServerFrame::Deliver { .. });
                    if let Some((_, line)) = handle_server_frame(session, &mut sink, frame).await? {
                        println!("{line}");
                    }
                    if is_deliver {
                        received += 1;
                    }
                }
            }
            Ok(Some(Err(_))) | Ok(None) => break,
            Err(_) => break, // quiet
        }
    }
    let _ = sink.close().await;
    Ok((flushed, received))
}

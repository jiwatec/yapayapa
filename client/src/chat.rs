//! Line-based CLI chat (Phase 2). The Ratatui TUI in `tui.rs` builds on the
//! same messaging core; this flow is the simple, dependable one.

use std::io::Write as _;

use futures_util::StreamExt;
use tokio::io::{AsyncBufReadExt, BufReader};
use uuid::Uuid;
use yapayapa_common::types::{ChatContent, ClientFrame};
use yapayapa_common::validate::MAX_TEXT_BYTES;

use crate::messaging::{
    compose_direct, connect_ws, flush_outbox, handle_server_frame, parse_server_frame,
    render_content, send_frame, WsSink, WsSource,
};
use crate::session::Session;
use crate::store::Contact;

pub enum ChatTarget {
    Direct(Contact),
    Group(Uuid, String),
}

impl ChatTarget {
    pub fn chat_id(&self) -> String {
        match self {
            ChatTarget::Direct(c) => c.user_id.to_string(),
            ChatTarget::Group(id, _) => id.to_string(),
        }
    }
    pub fn title(&self) -> String {
        match self {
            ChatTarget::Direct(c) => format!("@{}", c.username),
            ChatTarget::Group(_, name) => format!("#{name}"),
        }
    }
}

fn prompt() {
    print!("> ");
    let _ = std::io::stdout().flush();
}

pub fn print_history(session: &Session, target: &ChatTarget, limit: usize) -> anyhow::Result<()> {
    let chat_id = target.chat_id();
    let history = session.store.history(&chat_id, limit)?;
    for msg in &history {
        let who = if msg.direction == "out" {
            "me".to_string()
        } else {
            session
                .store
                .contact_by_id(msg.sender_id)?
                .map(|c| c.username)
                .unwrap_or_else(|| msg.sender_id.to_string())
        };
        println!(
            "[{}] {} {}: {}",
            msg.sent_at.format("%Y-%m-%d %H:%M"),
            msg.state.symbol(),
            who,
            render_content(&msg.content)
        );
        if matches!(msg.content, ChatContent::Image { .. }) {
            println!(
                "        ↳ view with `yapayapa open-image {}`",
                msg.message_id
            );
        }
    }
    if history.is_empty() {
        println!("(no messages yet)");
    }
    Ok(())
}

pub async fn run_chat(session: &Session, target: ChatTarget) -> anyhow::Result<()> {
    let chat_id = target.chat_id();
    println!("── chat with {} ──", target.title());
    print_history(session, &target, 50)?;
    session.store.mark_chat_read(&chat_id)?;

    if let ChatTarget::Group(group_id, _) = &target {
        if let Err(e) = crate::groups::ensure_current_key(session, *group_id).await {
            println!("! {e}");
        }
    }

    let mut ws: Option<(WsSink, WsSource)> = match connect_ws(session).await {
        Some(stream) => {
            let (mut sink, source) = stream.split();
            let flushed = flush_outbox(session, &mut sink).await?;
            if flushed > 0 {
                println!("(sent {flushed} queued message(s) from the outbox)");
            }
            println!("(online — connected to relay)");
            Some((sink, source))
        }
        None => {
            println!(
                "(OFFLINE — messages will be queued locally and sent when a connection returns)"
            );
            None
        }
    };

    println!("type a message and press Enter; /quit to exit");
    prompt();

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut retry = tokio::time::interval(std::time::Duration::from_secs(5));
    retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Some(line) = line? else { break };
                let text = line.trim();
                if text.is_empty() {
                    prompt();
                    continue;
                }
                if text == "/quit" || text == "/q" {
                    break;
                }
                if text.len() > MAX_TEXT_BYTES {
                    println!("! message too long (max {MAX_TEXT_BYTES} bytes)");
                    prompt();
                    continue;
                }
                let content = ChatContent::Text { body: text.to_string() };
                let result: anyhow::Result<()> = (|| {
                    match &target {
                        ChatTarget::Direct(contact) => {
                            let wire = compose_direct(session, contact, &content)?;
                            let _ = wire;
                            Ok(())
                        }
                        ChatTarget::Group(group_id, _) => {
                            crate::groups::compose_group(session, *group_id, &content)?;
                            Ok(())
                        }
                    }
                })();
                match result {
                    Ok(()) => {
                        if let Some((sink, _)) = &mut ws {
                            if flush_outbox(session, sink).await.is_err() {
                                println!("(connection lost — message queued locally)");
                                ws = None;
                            }
                        } else {
                            println!("(queued locally — offline)");
                        }
                    }
                    Err(e) => println!("! {e}"),
                }
                prompt();
            }

            frame = async { ws.as_mut().unwrap().1.next().await }, if ws.is_some() => {
                match frame {
                    Some(Ok(msg)) => {
                        if let Some(server_frame) = parse_server_frame(&msg) {
                            let (sink, _) = ws.as_mut().unwrap();
                            match handle_server_frame(session, sink, server_frame).await {
                                Ok(Some((frame_chat, line))) => {
                                    if frame_chat == chat_id {
                                        println!("\r{line}");
                                        session.store.mark_chat_read(&chat_id)?;
                                    } else if frame_chat.is_empty() {
                                        println!("\r{line}");
                                    } else {
                                        println!("\r(new message in another chat)");
                                    }
                                    prompt();
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    println!("\r! {e}");
                                    prompt();
                                }
                            }
                        }
                    }
                    _ => {
                        println!("\r(connection lost — now OFFLINE; will retry every 5s)");
                        prompt();
                        ws = None;
                    }
                }
            }

            _ = retry.tick() => {
                if ws.is_none() {
                    if let Some(stream) = connect_ws(session).await {
                        let (mut sink, source) = stream.split();
                        let flushed = flush_outbox(session, &mut sink).await.unwrap_or(0);
                        println!("\r(reconnected — online{})",
                            if flushed > 0 { format!(", sent {flushed} queued message(s)") } else { String::new() });
                        prompt();
                        ws = Some((sink, source));
                    }
                } else if let Some((sink, _)) = &mut ws {
                    // Keepalive.
                    let _ = send_frame(sink, &ClientFrame::Ping).await;
                }
            }
        }
    }
    println!("bye");
    Ok(())
}

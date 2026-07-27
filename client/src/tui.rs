//! Ratatui full-screen chat interface, layered on the same messaging core as
//! the CLI chat: chat sidebar with unread markers, scrollable history with
//! timestamps and sender names, connection status, and safe terminal
//! restore on exit (including Ctrl+C).

use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use futures_util::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, List, ListItem, Padding, Paragraph, Wrap};
use ratatui::Terminal;
use uuid::Uuid;
use yapayapa_common::types::ChatContent;
use yapayapa_common::validate::MAX_TEXT_BYTES;

use crate::chat::ChatTarget;
use crate::messaging::{
    compose_direct, connect_ws, flush_outbox, handle_server_frame, parse_server_frame,
    render_content, WsSink, WsSource,
};
use crate::session::Session;
use crate::store::LocalMessage;

/// Dark, opencode-inspired palette. RGB values need a truecolor terminal
/// (Windows Terminal, kitty, alacritty, foot, wezterm — all fine).
pub(crate) mod theme {
    use ratatui::style::Color;
    pub const BG: Color = Color::Rgb(14, 14, 18);
    pub const SURFACE: Color = Color::Rgb(28, 28, 36);
    pub const BORDER: Color = Color::Rgb(58, 58, 70);
    pub const TEXT: Color = Color::Rgb(215, 215, 225);
    pub const DIM: Color = Color::Rgb(115, 115, 130);
    pub const ACCENT: Color = Color::Rgb(250, 178, 131);
    pub const GREEN: Color = Color::Rgb(152, 195, 121);
    pub const RED: Color = Color::Rgb(224, 108, 117);
    pub const YELLOW: Color = Color::Rgb(229, 192, 123);
}

pub(crate) struct TermGuard;

impl TermGuard {
    pub(crate) fn new() -> anyhow::Result<Self> {
        enable_raw_mode()?;
        execute!(std::io::stdout(), EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
    }
}

#[derive(Clone)]
pub(crate) struct ChatEntry {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) is_group: bool,
    pub(crate) unread: i64,
}

struct App {
    chats: Vec<ChatEntry>,
    active: usize,
    messages: Vec<LocalMessage>,
    input: String,
    scroll_up: u16,
    online: bool,
    notice: Option<String>,
}

impl App {
    fn active_chat(&self) -> &ChatEntry {
        &self.chats[self.active]
    }
}

pub(crate) fn load_chats(
    session: &Session,
    ensure: Option<(&str, &str, bool)>,
) -> anyhow::Result<Vec<ChatEntry>> {
    let mut chats = Vec::new();
    for c in session.store.list_contacts()? {
        let id = c.user_id.to_string();
        chats.push(ChatEntry {
            unread: session.store.unread_count(&id)?,
            id,
            title: format!("@{}", c.username),
            is_group: false,
        });
    }
    for (gid, name, _) in session.store.list_groups()? {
        let id = gid.to_string();
        chats.push(ChatEntry {
            unread: session.store.unread_count(&id)?,
            id,
            title: format!("#{name}"),
            is_group: true,
        });
    }
    if let Some((ensure_id, ensure_title, ensure_group)) = ensure {
        if !chats.iter().any(|c| c.id == ensure_id) {
            chats.push(ChatEntry {
                id: ensure_id.to_string(),
                title: ensure_title.to_string(),
                is_group: ensure_group,
                unread: 0,
            });
        }
    }
    Ok(chats)
}

pub async fn run(session: &Session, target: ChatTarget) -> anyhow::Result<()> {
    let (ensure_id, ensure_title, ensure_group) = match &target {
        ChatTarget::Direct(c) => (c.user_id.to_string(), format!("@{}", c.username), false),
        ChatTarget::Group(id, name) => (id.to_string(), format!("#{name}"), true),
    };
    let chats = load_chats(session, Some((&ensure_id, &ensure_title, ensure_group)))?;
    let active = chats.iter().position(|c| c.id == ensure_id).unwrap_or(0);

    let mut app = App {
        chats,
        active,
        messages: Vec::new(),
        input: String::new(),
        scroll_up: 0,
        online: false,
        notice: None,
    };
    app.messages = session.store.history(&app.active_chat().id.clone(), 200)?;
    session
        .store
        .mark_chat_read(&app.active_chat().id.clone())?;

    let mut ws: Option<(WsSink, WsSource)> = match connect_ws(session).await {
        Some(stream) => {
            let (mut sink, source) = stream.split();
            let _ = flush_outbox(session, &mut sink).await;
            app.online = true;
            Some((sink, source))
        }
        None => None,
    };

    let _guard = TermGuard::new()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;
    let mut events = EventStream::new();
    let mut retry = tokio::time::interval(std::time::Duration::from_secs(5));
    retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        terminal.draw(|f| draw(f, session, &app))?;

        tokio::select! {
            ev = events.next() => {
                let Some(Ok(ev)) = ev else { break };
                if let Event::Resize(_, _) = ev {
                    // Full repaint so the layout adapts to the new size.
                    terminal.clear()?;
                    continue;
                }
                if let Event::Key(key) = ev {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    let ctrl_c = key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL);
                    if ctrl_c || key.code == KeyCode::Esc {
                        break;
                    }
                    match key.code {
                        KeyCode::Enter => {
                            let text = app.input.trim().to_string();
                            app.input.clear();
                            if text.is_empty() { continue; }
                            if text.len() > MAX_TEXT_BYTES {
                                app.notice = Some("message too long".into());
                                continue;
                            }
                            let content = ChatContent::Text { body: text };
                            let chat = app.active_chat().clone();
                            let result = if chat.is_group {
                                chat.id.parse::<Uuid>()
                                    .map_err(anyhow::Error::from)
                                    .and_then(|gid| crate::groups::compose_group(session, gid, &content).map(|_| ()))
                            } else {
                                session.store.contact_by_id(chat.id.parse()?)?
                                    .ok_or_else(|| anyhow::anyhow!("unknown contact"))
                                    .and_then(|c| compose_direct(session, &c, &content).map(|_| ()))
                            };
                            match result {
                                Ok(()) => {
                                    if let Some((sink, _)) = &mut ws {
                                        if flush_outbox(session, sink).await.is_err() {
                                            ws = None;
                                            app.online = false;
                                        }
                                    }
                                }
                                Err(e) => app.notice = Some(format!("{e}")),
                            }
                            app.messages = session.store.history(&chat.id, 200)?;
                            app.scroll_up = 0;
                        }
                        KeyCode::Backspace => { app.input.pop(); }
                        KeyCode::Char(c) => { app.input.push(c); }
                        KeyCode::Up | KeyCode::PageUp => {
                            app.scroll_up = app.scroll_up.saturating_add(if key.code == KeyCode::PageUp { 10 } else { 1 });
                        }
                        KeyCode::Down | KeyCode::PageDown => {
                            app.scroll_up = app.scroll_up.saturating_sub(if key.code == KeyCode::PageDown { 10 } else { 1 });
                        }
                        KeyCode::Tab | KeyCode::BackTab => {
                            let n = app.chats.len();
                            app.active = if key.code == KeyCode::Tab {
                                (app.active + 1) % n
                            } else {
                                (app.active + n - 1) % n
                            };
                            let id = app.active_chat().id.clone();
                            app.messages = session.store.history(&id, 200)?;
                            session.store.mark_chat_read(&id)?;
                            app.chats[app.active].unread = 0;
                            app.scroll_up = 0;
                        }
                        _ => {}
                    }
                }
            }

            frame = async { ws.as_mut().unwrap().1.next().await }, if ws.is_some() => {
                match frame {
                    Some(Ok(msg)) => {
                        if let Some(server_frame) = parse_server_frame(&msg) {
                            let (sink, _) = ws.as_mut().unwrap();
                            if let Ok(Some((chat_id, _line))) =
                                handle_server_frame(session, sink, server_frame).await
                            {
                                if chat_id == app.active_chat().id {
                                    session.store.mark_chat_read(&chat_id)?;
                                } else if let Some(entry) =
                                    app.chats.iter_mut().find(|c| c.id == chat_id)
                                {
                                    entry.unread = session.store.unread_count(&chat_id)?;
                                }
                            }
                        }
                        let id = app.active_chat().id.clone();
                        app.messages = session.store.history(&id, 200)?;
                    }
                    _ => {
                        ws = None;
                        app.online = false;
                    }
                }
            }

            _ = retry.tick() => {
                if ws.is_none() {
                    if let Some(stream) = connect_ws(session).await {
                        let (mut sink, source) = stream.split();
                        let _ = flush_outbox(session, &mut sink).await;
                        ws = Some((sink, source));
                        app.online = true;
                    }
                }
                let id = app.active_chat().id.clone();
                app.messages = session.store.history(&id, 200)?;
            }
        }
    }
    Ok(())
}

fn draw(f: &mut ratatui::Frame, session: &Session, app: &App) {
    use theme::*;

    // Full dark canvas behind everything.
    f.render_widget(Block::default().style(Style::default().bg(BG)), f.area());

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(5),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(f.area());
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(24), Constraint::Min(30)])
        .split(rows[0]);

    // Sidebar: chat list with unread badges; the active chat gets an accent bar.
    let items: Vec<ListItem> = app
        .chats
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let selected = i == app.active;
            let title_style = if selected {
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
            } else if c.unread > 0 {
                Style::default().fg(YELLOW).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(TEXT)
            };
            let mut spans = vec![
                Span::styled(
                    if selected { "▌ " } else { "  " },
                    Style::default().fg(ACCENT),
                ),
                Span::styled(c.title.clone(), title_style),
            ];
            if c.unread > 0 {
                spans.push(Span::styled(
                    format!(" {}", c.unread),
                    Style::default().fg(YELLOW).add_modifier(Modifier::BOLD),
                ));
            }
            let mut item = ListItem::new(Line::from(spans));
            if selected {
                item = item.style(Style::default().bg(SURFACE));
            }
            item
        })
        .collect();
    f.render_widget(
        List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(BORDER))
                .title(Span::styled(" Chats ", Style::default().fg(DIM))),
        ),
        cols[0],
    );

    // Conversation.
    let me = session.keystore.profile.user_id;
    let mut lines: Vec<Line> = Vec::new();
    for m in &app.messages {
        let who = if m.sender_id == me {
            "me".to_string()
        } else {
            session
                .store
                .contact_by_id(m.sender_id)
                .ok()
                .flatten()
                .map(|c| c.username)
                .unwrap_or_else(|| "?".into())
        };
        let state = if m.direction == "out" {
            format!(" {}", m.state.symbol())
        } else {
            String::new()
        };
        let color = if m.sender_id == me { ACCENT } else { GREEN };
        lines.push(Line::from(vec![
            Span::styled(
                format!("{} ", m.sent_at.format("%H:%M")),
                Style::default().fg(DIM),
            ),
            Span::styled(
                format!("{who} "),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(render_content(&m.content), Style::default().fg(TEXT)),
            Span::styled(state, Style::default().fg(DIM)),
        ]));
    }
    let inner_height = cols[1].height.saturating_sub(2);
    let total = lines.len() as u16;
    let base = total.saturating_sub(inner_height);
    let scroll = base.saturating_sub(app.scroll_up);
    let mut msg_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER))
        .padding(Padding::horizontal(1))
        .title(Span::styled(
            format!(" {} ", app.active_chat().title),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ));
    if app.scroll_up > 0 {
        msg_block = msg_block.title_bottom(
            Line::from(Span::styled(
                " ↑ viewing older messages ",
                Style::default().fg(YELLOW),
            ))
            .right_aligned(),
        );
    }
    f.render_widget(
        Paragraph::new(lines)
            .block(msg_block)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        cols[1],
    );

    // Input: prompt-style with a live cursor.
    let input_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(ACCENT))
        .title(Span::styled(" Message ", Style::default().fg(DIM)));
    let inner = input_block.inner(rows[1]);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                "› ",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled(app.input.as_str(), Style::default().fg(TEXT)),
        ]))
        .block(input_block),
        rows[1],
    );
    let cursor_x = inner.x + 2 + app.input.chars().count() as u16;
    f.set_cursor_position((cursor_x.min(inner.right().saturating_sub(1)), inner.y));

    // Status bar: state on the left, key hints on the right.
    let queued = session.store.outbox_list().map(|o| o.len()).unwrap_or(0);
    let mut left: Vec<Span> = Vec::new();
    if app.online {
        left.push(Span::styled(" ● online ", Style::default().fg(GREEN)));
    } else {
        left.push(Span::styled(
            " ○ offline — saving to encrypted outbox ",
            Style::default().fg(RED).add_modifier(Modifier::BOLD),
        ));
    }
    if queued > 0 {
        left.push(Span::styled(
            format!(" {queued} queued "),
            Style::default().fg(YELLOW),
        ));
    }
    if let Some(n) = &app.notice {
        left.push(Span::styled(format!(" {n} "), Style::default().fg(RED)));
    }
    let hints = " Tab chats · ↑/↓ scroll · Enter send · Esc quit ";
    let used: usize = left
        .iter()
        .map(|s| s.content.chars().count())
        .sum::<usize>()
        + hints.chars().count();
    let pad = (rows[2].width as usize).saturating_sub(used);
    left.push(Span::raw(" ".repeat(pad)));
    left.push(Span::styled(hints, Style::default().fg(DIM)));
    f.render_widget(
        Paragraph::new(Line::from(left)).style(Style::default().bg(SURFACE)),
        rows[2],
    );
}

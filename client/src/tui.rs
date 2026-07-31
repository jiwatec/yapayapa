//! Ratatui full-screen chat interface, layered on the same messaging core as
//! the CLI chat: chat sidebar with unread markers, scrollable history with
//! timestamps and sender names, connection status, and safe terminal
//! restore on exit (including Ctrl+C).

use crossterm::event::{
    DisableBracketedPaste, EnableBracketedPaste, Event, EventStream, KeyCode, KeyEventKind,
    KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use futures_util::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, List, ListItem, Padding, Paragraph, Wrap,
};
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

    /// Distinct, readable name colors assigned per group member so each
    /// speaker is easy to tell apart. `sender_color` picks one deterministically.
    pub const SENDER_COLORS: &[Color] = &[
        Color::Rgb(152, 195, 121), // green
        Color::Rgb(97, 175, 239),  // blue
        Color::Rgb(198, 120, 221), // purple
        Color::Rgb(86, 182, 194),  // teal
        Color::Rgb(229, 192, 123), // gold
        Color::Rgb(236, 154, 195), // pink
        Color::Rgb(129, 200, 190), // mint
        Color::Rgb(212, 154, 106), // amber
    ];
}

/// Stable per-user name color from the palette (same user, same color across
/// launches), so group members keep a consistent, distinct color.
fn sender_color(id: Uuid) -> ratatui::style::Color {
    let sum = id
        .as_bytes()
        .iter()
        .fold(0u32, |acc, &b| acc.wrapping_add(b as u32));
    theme::SENDER_COLORS[sum as usize % theme::SENDER_COLORS.len()]
}

pub(crate) struct TermGuard;

impl TermGuard {
    pub(crate) fn new() -> anyhow::Result<Self> {
        enable_raw_mode()?;
        execute!(std::io::stdout(), EnterAlternateScreen, EnableBracketedPaste)?;
        Ok(Self)
    }
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen, DisableBracketedPaste);
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
    /// Highlighted row in the `/` command menu (when it's showing).
    menu_sel: usize,
}

impl App {
    fn active_chat(&self) -> &ChatEntry {
        &self.chats[self.active]
    }
}

/// A slash command offered by the `/` command menu inside a chat.
struct SlashCmd {
    /// Word after the slash, e.g. "add" for `/add`.
    name: &'static str,
    /// Full usage shown in the menu, e.g. "/add <user>".
    usage: &'static str,
    /// One-line description of what it does.
    desc: &'static str,
    /// Whether it expects an argument (so completing leaves a trailing space).
    takes_arg: bool,
    /// Only offered while a group chat is open.
    group_only: bool,
}

const SLASH_COMMANDS: &[SlashCmd] = &[
    SlashCmd {
        name: "add",
        usage: "/add <user>",
        desc: "add a member to this group",
        takes_arg: true,
        group_only: true,
    },
    SlashCmd {
        name: "members",
        usage: "/members",
        desc: "list this group's members",
        takes_arg: false,
        group_only: true,
    },
    SlashCmd {
        name: "img",
        usage: "/img <path>",
        desc: "send an encrypted image",
        takes_arg: true,
        group_only: false,
    },
    SlashCmd {
        name: "clear",
        usage: "/clear",
        desc: "wipe this chat's local history",
        takes_arg: false,
        group_only: false,
    },
];

/// Commands the `/` menu should show for the current input: only while the
/// user is typing a command word (input starts with `/`, no space yet), the
/// name prefix-matches, and group-only commands are hidden in direct chats.
fn command_matches(app: &App) -> Vec<&'static SlashCmd> {
    if !app.input.starts_with('/') || app.input.contains(' ') {
        return Vec::new();
    }
    let prefix = &app.input[1..];
    let is_group = app.active_chat().is_group;
    SLASH_COMMANDS
        .iter()
        .filter(|c| (is_group || !c.group_only) && c.name.starts_with(prefix))
        .collect()
}

/// The currently highlighted command in the menu, if the menu is showing.
fn selected_command(app: &App) -> Option<&'static SlashCmd> {
    let matches = command_matches(app);
    if matches.is_empty() {
        None
    } else {
        Some(matches[app.menu_sel.min(matches.len() - 1)])
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
        menu_sel: 0,
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

    // Refresh group membership on open so freshly-added members/keys pull
    // automatically (no manual `sync` + `groups info`). Best-effort; offline
    // just keeps the existing cache. Reload the active chat's history after so
    // any newly-pinned members are reflected right away.
    if app.online {
        crate::groups::sync_all_groups(session).await;
        app.messages = session.store.history(&app.active_chat().id.clone(), 200)?;
    }

    let _guard = TermGuard::new()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;
    let mut events = EventStream::new();
    let mut retry = tokio::time::interval(std::time::Duration::from_secs(5));
    retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Two-step confirm state for the /clear command.
    let mut clear_armed = false;

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
                if let Event::Paste(data) = ev {
                    // Collapse newlines so a multi-line paste stays one message line.
                    let cleaned = data.replace(['\n', '\r'], " ");
                    app.input.push_str(&cleaned);
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
                            // The `/` command menu is open: Enter accepts the
                            // highlighted command. Commands that take an argument
                            // just complete the input and wait for it; no-arg
                            // commands complete and fall through to run now.
                            if let Some(cmd) = selected_command(&app) {
                                app.menu_sel = 0;
                                if cmd.takes_arg {
                                    app.input = format!("/{} ", cmd.name);
                                    continue;
                                }
                                app.input = format!("/{}", cmd.name);
                            }
                            let text = app.input.trim().to_string();
                            app.input.clear();
                            if text.is_empty() { continue; }

                            // /clear — wipe the current chat's local history,
                            // with a two-step confirm so it isn't accidental.
                            if text == "/clear" {
                                let chat = app.active_chat().clone();
                                if clear_armed {
                                    session.store.clear_chat(&chat.id)?;
                                    app.messages = session.store.history(&chat.id, 200)?;
                                    app.scroll_up = 0;
                                    app.notice = Some("chat cleared".into());
                                    clear_armed = false;
                                } else {
                                    clear_armed = true;
                                    app.notice = Some(
                                        "type /clear again to confirm (wipes local history)".into(),
                                    );
                                }
                                continue;
                            }
                            clear_armed = false;

                            // /img <path> — send an encrypted image to the open
                            // chat without leaving it (mirrors `yapayapa img`).
                            if let Some(rest) = text
                                .strip_prefix("/img ")
                                .or_else(|| text.strip_prefix("/image "))
                            {
                                let raw = rest.trim();
                                if raw.is_empty() {
                                    app.notice = Some("usage: /img <path>".into());
                                    continue;
                                }
                                let path = expand_tilde(raw);
                                let chat = app.active_chat().clone();
                                app.notice = Some("sending image…".into());
                                terminal.draw(|f| draw(f, session, &app))?;
                                match send_image_in_chat(session, &chat, &path).await {
                                    Ok(()) => {
                                        app.notice = None;
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
                                continue;
                            }

                            // /members — list the current group's members,
                            // straight from the local cache (refreshed on open).
                            if text == "/members" {
                                let chat = app.active_chat().clone();
                                match group_members_line(session, &chat) {
                                    Ok(line) => app.notice = Some(line),
                                    Err(e) => app.notice = Some(format!("{e}")),
                                }
                                continue;
                            }

                            // /add <user> — add someone to the open group chat
                            // without dropping to the terminal (also dodges the
                            // `groups` shell-builtin collision). Mirrors
                            // `yapayapa groups add-member`.
                            if let Some(rest) = text
                                .strip_prefix("/add ")
                                .or_else(|| text.strip_prefix("/addmember "))
                            {
                                let user = rest.trim().to_string();
                                if user.is_empty() {
                                    app.notice = Some("usage: /add <username>".into());
                                    continue;
                                }
                                let chat = app.active_chat().clone();
                                app.notice = Some(format!("adding {user}…"));
                                terminal.draw(|f| draw(f, session, &app))?;
                                match add_member_in_chat(session, &chat, &user).await {
                                    Ok(line) => {
                                        app.notice = Some(line);
                                        // Flush the queued per-member key
                                        // envelopes so the new member can decrypt.
                                        if let Some((sink, _)) = &mut ws {
                                            if flush_outbox(session, sink).await.is_err() {
                                                ws = None;
                                                app.online = false;
                                            }
                                        }
                                    }
                                    Err(e) => app.notice = Some(format!("{e}")),
                                }
                                continue;
                            }

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
                        KeyCode::Backspace => { app.input.pop(); app.menu_sel = 0; }
                        KeyCode::Char(c) => { app.input.push(c); app.menu_sel = 0; }
                        // While the `/` menu is open, ↑/↓ move the selection;
                        // otherwise they scroll the conversation as before.
                        KeyCode::Up | KeyCode::PageUp if !command_matches(&app).is_empty() => {
                            app.menu_sel = app.menu_sel.saturating_sub(1);
                        }
                        KeyCode::Down | KeyCode::PageDown if !command_matches(&app).is_empty() => {
                            let last = command_matches(&app).len().saturating_sub(1);
                            app.menu_sel = (app.menu_sel + 1).min(last);
                        }
                        KeyCode::Up | KeyCode::PageUp => {
                            app.scroll_up = app.scroll_up.saturating_add(if key.code == KeyCode::PageUp { 10 } else { 1 });
                        }
                        KeyCode::Down | KeyCode::PageDown => {
                            app.scroll_up = app.scroll_up.saturating_sub(if key.code == KeyCode::PageDown { 10 } else { 1 });
                        }
                        // Tab completes the highlighted command when the menu is
                        // open; otherwise it cycles between chats.
                        KeyCode::Tab if selected_command(&app).is_some() => {
                            if let Some(cmd) = selected_command(&app) {
                                app.input = format!("/{} ", cmd.name);
                                app.menu_sel = 0;
                            }
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

    // Conversation. Chat-app styling: your own messages are right-aligned,
    // the other side's are left-aligned, consecutive messages from the same
    // speaker are grouped (name shown once, blank line between speakers).
    let me = session.keystore.profile.user_id;
    let mut lines: Vec<Line> = Vec::new();
    let mut prev_sender: Option<Uuid> = None;
    for m in &app.messages {
        let is_me = m.sender_id == me;
        let new_speaker = prev_sender != Some(m.sender_id);
        // Breathing room between different speakers' runs.
        if new_speaker && prev_sender.is_some() {
            lines.push(Line::from(""));
        }
        // Sender label once per run — only for the other side; right alignment
        // already marks your own messages.
        if new_speaker && !is_me {
            let who = session
                .store
                .contact_by_id(m.sender_id)
                .ok()
                .flatten()
                .map(|c| c.username)
                .unwrap_or_else(|| "?".into());
            // Per-speaker color in groups so everyone is distinct; a single
            // 1:1 partner just stays green.
            let name_color = if app.active_chat().is_group {
                sender_color(m.sender_id)
            } else {
                GREEN
            };
            lines.push(Line::from(Span::styled(
                who,
                Style::default().fg(name_color).add_modifier(Modifier::BOLD),
            )));
        }
        let time = format!("{}", m.sent_at.format("%H:%M"));
        let body = render_content(&m.content);
        if is_me {
            let state = format!(" {}", m.state.symbol());
            lines.push(
                Line::from(vec![
                    Span::styled(body, Style::default().fg(TEXT)),
                    Span::styled(format!("  {time}"), Style::default().fg(DIM)),
                    Span::styled(state, Style::default().fg(DIM)),
                ])
                .right_aligned(),
            );
        } else {
            lines.push(Line::from(vec![
                Span::styled(format!("{time}  "), Style::default().fg(DIM)),
                Span::styled(body, Style::default().fg(TEXT)),
            ]));
        }
        prev_sender = Some(m.sender_id);
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

    // Command menu: when the user is typing a `/command`, float the matching
    // commands just above the input box so they can pick instead of memorizing.
    let matches = command_matches(app);
    if !matches.is_empty() {
        let sel = app.menu_sel.min(matches.len() - 1);
        let items: Vec<ListItem> = matches
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let selected = i == sel;
                let name_style = if selected {
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(TEXT)
                };
                let line = Line::from(vec![
                    Span::styled(format!(" {:<14}", c.usage), name_style),
                    Span::styled(format!("{} ", c.desc), Style::default().fg(DIM)),
                ]);
                let mut item = ListItem::new(line);
                if selected {
                    item = item.style(Style::default().bg(SURFACE));
                }
                item
            })
            .collect();
        // Height = rows + borders, clamped to the space above the input.
        let h = (matches.len() as u16 + 2).min(rows[1].y.saturating_sub(rows[0].y));
        let area = Rect {
            x: cols[1].x,
            y: rows[1].y.saturating_sub(h),
            width: cols[1].width,
            height: h,
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(ACCENT))
            .title(Span::styled(
                " commands · ↑/↓ select · Enter run · Tab complete ",
                Style::default().fg(DIM),
            ));
        f.render_widget(Clear, area);
        f.render_widget(List::new(items).block(block), area);
    }

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
    let hints = " Tab chats · ↑/↓ scroll · Esc quit ";
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

/// Expand a leading `~/` to the home directory (the TUI has no shell to do it).
fn expand_tilde(p: &str) -> std::path::PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return std::path::Path::new(&home).join(rest);
        }
    }
    std::path::PathBuf::from(p)
}

/// Add a member to the open group chat, mirroring `yapayapa groups add-member`:
/// call the server, rotate + re-cache the group key, and return a status line.
/// The queued key envelopes are flushed by the caller. Errors out for a direct
/// chat (nothing to add someone to).
async fn add_member_in_chat(
    session: &Session,
    chat: &ChatEntry,
    user: &str,
) -> anyhow::Result<String> {
    if !chat.is_group {
        anyhow::bail!("/add only works in a group chat");
    }
    let gid: Uuid = chat.id.parse()?;
    let info = session
        .api
        .add_group_member(gid, user)
        .await
        .map_err(|e| anyhow::anyhow!("add failed: {e}"))?;
    let queued = crate::groups::rotate_group_key(session, &info)?;
    Ok(format!(
        "added @{user}; rotated key to epoch {} ({queued} key message(s) queued)",
        info.key_epoch
    ))
}

/// One-line summary of the open group's members, from the local cache.
fn group_members_line(session: &Session, chat: &ChatEntry) -> anyhow::Result<String> {
    if !chat.is_group {
        anyhow::bail!("/members only works in a group chat");
    }
    let gid: Uuid = chat.id.parse()?;
    let me = session.keystore.profile.user_id;
    let mut names = vec!["you".to_string()];
    for id in session.store.cached_group_members(gid)? {
        if id == me {
            continue;
        }
        let name = session
            .store
            .contact_by_id(id)?
            .map(|c| format!("@{}", c.username))
            .unwrap_or_else(|| id.to_string());
        names.push(name);
    }
    Ok(format!("members ({}): {}", names.len(), names.join(", ")))
}

/// Encrypt and send an image to the chat that is currently open, reusing the
/// same attachment pipeline as the `yapayapa img` command.
async fn send_image_in_chat(
    session: &Session,
    chat: &ChatEntry,
    path: &std::path::Path,
) -> anyhow::Result<()> {
    if !path.exists() {
        anyhow::bail!("no such file: {}", path.display());
    }
    if chat.is_group {
        let gid: Uuid = chat.id.parse()?;
        crate::groups::ensure_current_key(session, gid).await?;
        let me = session.keystore.profile.user_id;
        let members: Vec<Uuid> = session
            .store
            .cached_group_members(gid)?
            .into_iter()
            .filter(|m| *m != me)
            .collect();
        if members.is_empty() {
            anyhow::bail!("group has no other members");
        }
        let content = crate::attach::encrypt_and_upload(session, path, &members).await?;
        let history_id = crate::groups::compose_group(session, gid, &content)?;
        crate::messaging::store_outgoing_attachment(session, history_id, &content)?;
    } else {
        let contact = session
            .store
            .contact_by_id(chat.id.parse()?)?
            .ok_or_else(|| anyhow::anyhow!("unknown contact"))?;
        let content = crate::attach::encrypt_and_upload(session, path, &[contact.user_id]).await?;
        let wire = compose_direct(session, &contact, &content)?;
        crate::messaging::store_outgoing_attachment(session, wire.message_id, &content)?;
    }
    Ok(())
}

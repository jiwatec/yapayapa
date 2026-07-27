//! Launcher home screen shown by bare `yapayapa`: centered pixel wordmark
//! with a prompt box below it. Enter opens the pre-selected chat, typed
//! text runs as a command (or opens a chat with that name), Tab shows a
//! command reference, and Ctrl+P opens a choose-and-run palette.
//! With no account yet it shows the setup steps instead.

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph};
use ratatui::Terminal;
use uuid::Uuid;

use crate::chat::ChatTarget;
use crate::config::Config;
use crate::session::Session;
use crate::tui::theme::*;
use crate::tui::{load_chats, ChatEntry};

/// 6x5 chunky pixel glyphs (2-cell stroke width) for the wordmark.
fn glyph(c: char) -> [&'static str; 5] {
    match c {
        'Y' => ["##..##", "##..##", ".####.", "..##..", "..##.."],
        'A' => [".####.", "##..##", "######", "##..##", "##..##"],
        'P' => ["#####.", "##..##", "#####.", "##....", "##...."],
        _ => ["......", "......", "......", "......", "......"],
    }
}

/// Two-tone YAPAYAPA wordmark in the chat theme: dim half, bright half.
pub(crate) fn logo_lines() -> Vec<Line<'static>> {
    let word = "YAPAYAPA";
    (0..5)
        .map(|row| {
            let mut spans = Vec::new();
            for (i, c) in word.chars().enumerate() {
                let color = if i < 4 { DIM } else { TEXT };
                let pixels: String = glyph(c)[row]
                    .chars()
                    .map(|p| if p == '#' { '█' } else { ' ' })
                    .collect();
                spans.push(Span::styled(pixels, Style::default().fg(color)));
                if i + 1 < word.len() {
                    spans.push(Span::raw(" "));
                }
            }
            Line::from(spans).centered()
        })
        .collect()
}

/// What choosing a palette entry does.
enum PaletteAction {
    /// Open the currently selected chat.
    OpenSelected,
    /// Run this command line immediately.
    Exec(&'static str),
    /// Put this prefix in the input so the user finishes it.
    Prefill(&'static str),
}

/// name, what-it-does, action. One source for both the palette and Tab help.
const COMMANDS: &[(&str, &str, PaletteAction)] = &[
    (
        "chat",
        "open the selected chat",
        PaletteAction::OpenSelected,
    ),
    (
        "add <user>",
        "add a contact by name or public ID",
        PaletteAction::Prefill("add "),
    ),
    (
        "friends",
        "list your contacts",
        PaletteAction::Exec("friends"),
    ),
    (
        "group <name>",
        "create a group chat",
        PaletteAction::Prefill("group "),
    ),
    (
        "img <to> <file>",
        "send an encrypted image",
        PaletteAction::Prefill("img "),
    ),
    (
        "sync",
        "send queued offline messages",
        PaletteAction::Exec("sync"),
    ),
    (
        "status",
        "connection, outbox and unread counts",
        PaletteAction::Exec("status"),
    ),
    (
        "verify <user>",
        "compare fingerprints with a contact",
        PaletteAction::Prefill("verify "),
    ),
    (
        "profile",
        "show your username, public ID, fingerprint",
        PaletteAction::Exec("profile"),
    ),
    (
        "outbox",
        "show queued not-yet-sent messages",
        PaletteAction::Exec("outbox"),
    ),
];

enum Overlay {
    None,
    Help,
    Palette(usize),
    /// Error shown inline on the input box (red border); enter clears it.
    Error(String),
    /// Command output shown inline on the input box; enter clears it.
    Output(String),
}

enum HomeAction {
    Quit,
    /// Open a chat with this target (chat id or typed name).
    Open(String),
    /// Run this typed command line outside the TUI.
    Exec(String),
}

pub async fn run(config: Config) -> anyhow::Result<()> {
    let Some((session, password, mut online)) = crate::auth::establish_session(&config).await?
    else {
        return Ok(());
    };
    // Text to show inline on the input box next time round: (message, ok).
    let mut notice: Option<(String, bool)> = None;

    loop {
        let chats = load_chats(&session, None)?;
        match home_screen(&session, &chats, online, notice.take())? {
            HomeAction::Quit => return Ok(()),
            HomeAction::Open(spec) => match resolve_target(&session, &chats, &spec).await {
                Ok(target) => {
                    crate::tui::run(&session, target).await?;
                    online = session.api.health().await;
                }
                Err(e) => notice = Some((format!("{e}"), false)),
            },
            HomeAction::Exec(line) => {
                if is_command(&line) {
                    // Captured re-run of the CLI: both output and errors show
                    // inline on the home screen's input box.
                    let result = run_captured(&config, &password, &line).await;
                    notice = Some(result);
                    online = session.api.health().await;
                } else {
                    match resolve_target(&session, &chats, &line).await {
                        Ok(target) => {
                            crate::tui::run(&session, target).await?;
                            online = session.api.health().await;
                        }
                        Err(e) => notice = Some((format!("{e}"), false)),
                    }
                }
            }
        }
    }
}

/// Command words the home screen runs in place (everything else is treated
/// as a chat target).
fn is_command(line: &str) -> bool {
    matches!(
        line.split_whitespace().next().unwrap_or(""),
        "friends"
            | "sync"
            | "status"
            | "profile"
            | "identity"
            | "outbox"
            | "add"
            | "find"
            | "verify"
            | "group"
            | "groups"
            | "img"
            | "contacts"
            | "peers"
            | "send-image"
            | "open-image"
            | "attachments"
            | "register"
            | "login"
            | "logout"
    )
}

/// Re-run this binary with the typed command line, feeding it the session
/// password, and capture everything it prints. Returns the output and
/// whether the command succeeded.
async fn run_captured(config: &Config, password: &str, line: &str) -> (String, bool) {
    let args: Vec<String> = line.split_whitespace().map(str::to_string).collect();
    let data_dir = config.data_dir.clone();
    let server = config.server.clone();
    let password = password.to_string();
    let run = tokio::task::spawn_blocking(move || {
        let exe = std::env::current_exe()?;
        std::process::Command::new(exe)
            .args(&args)
            .env("YAPAYAPA_PASSWORD", &password)
            .env("YAPAYAPA_DATA_DIR", &data_dir)
            .env("YAPAYAPA_SERVER", &server)
            .output()
    })
    .await;
    match run {
        Ok(Ok(out)) => {
            if out.status.success() {
                let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
                let err = String::from_utf8_lossy(&out.stderr);
                if !err.trim().is_empty() {
                    if !text.trim().is_empty() {
                        text.push('\n');
                    }
                    text.push_str(err.trim_end());
                }
                if text.trim().is_empty() {
                    ("done".into(), true)
                } else {
                    (text, true)
                }
            } else {
                // The CLI prints `error: <msg>` on stderr; keep anything it
                // printed on stdout first, then the message itself.
                let mut text = String::from_utf8_lossy(&out.stdout).trim_end().to_string();
                let err = String::from_utf8_lossy(&out.stderr);
                let msg = err.trim().trim_start_matches("error:").trim();
                if !msg.is_empty() {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(msg);
                }
                if text.trim().is_empty() {
                    ("command failed".into(), false)
                } else {
                    (text, false)
                }
            }
        }
        Ok(Err(e)) => (format!("{e}"), false),
        Err(e) => (format!("{e}"), false),
    }
}

/// Turn what the user picked or typed into a chat target.
async fn resolve_target(
    session: &Session,
    chats: &[ChatEntry],
    spec: &str,
) -> anyhow::Result<ChatTarget> {
    // Accept "chat buddy" and "@buddy" spellings too.
    let name = spec
        .trim()
        .strip_prefix("chat ")
        .unwrap_or(spec.trim())
        .trim_start_matches('@');
    let entry = chats
        .iter()
        .find(|c| c.id == name || c.title.trim_start_matches(['@', '#']) == name);
    if let Some(entry) = entry {
        return entry_target(session, entry);
    }
    let contact = crate::commands::resolve_contact(session, name, false).await?;
    Ok(ChatTarget::Direct(contact))
}

fn entry_target(session: &Session, entry: &ChatEntry) -> anyhow::Result<ChatTarget> {
    if entry.is_group {
        let gid: Uuid = entry.id.parse()?;
        Ok(ChatTarget::Group(
            gid,
            entry.title.trim_start_matches('#').to_string(),
        ))
    } else {
        let contact = session
            .store
            .contact_by_id(entry.id.parse()?)?
            .ok_or_else(|| anyhow::anyhow!("unknown contact"))?;
        Ok(ChatTarget::Direct(contact))
    }
}

/// Blocking home screen loop; returns when the user opens a chat, runs a
/// command, or quits.
fn home_screen(
    session: &Session,
    chats: &[ChatEntry],
    online: bool,
    notice: Option<(String, bool)>,
) -> anyhow::Result<HomeAction> {
    let _guard = crate::tui::TermGuard::new()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;
    let mut input = String::new();
    let mut selected: usize = 0;
    let mut overlay = match notice {
        Some((n, true)) => Overlay::Output(n),
        Some((n, false)) => Overlay::Error(n),
        None => Overlay::None,
    };

    loop {
        terminal.draw(|f| draw_home(f, session, chats, online, selected, &input, &overlay))?;
        let key = match event::read()? {
            Event::Key(key) => key,
            Event::Resize(_, _) => {
                // Full repaint so the layout re-centers at the new size.
                terminal.clear()?;
                continue;
            }
            _ => continue,
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('c') {
            return Ok(HomeAction::Quit);
        }
        match &mut overlay {
            Overlay::Help => {
                overlay = Overlay::None;
            }
            Overlay::Error(_) | Overlay::Output(_) => {
                if key.code == KeyCode::Enter {
                    overlay = Overlay::None;
                }
            }
            Overlay::Palette(cursor) => match key.code {
                KeyCode::Esc => overlay = Overlay::None,
                KeyCode::Char('p') if ctrl => overlay = Overlay::None,
                KeyCode::Up => *cursor = (*cursor + COMMANDS.len() - 1) % COMMANDS.len(),
                KeyCode::Down | KeyCode::Tab => *cursor = (*cursor + 1) % COMMANDS.len(),
                KeyCode::Enter => {
                    let (_, _, action) = &COMMANDS[*cursor];
                    match action {
                        PaletteAction::OpenSelected => {
                            if let Some(entry) = chats.get(selected) {
                                return Ok(HomeAction::Open(entry.id.clone()));
                            }
                            overlay = Overlay::Error("no chats yet — try `add <friend>`".into());
                        }
                        PaletteAction::Exec(cmdline) => {
                            return Ok(HomeAction::Exec(cmdline.to_string()));
                        }
                        PaletteAction::Prefill(prefix) => {
                            input = prefix.to_string();
                            overlay = Overlay::None;
                        }
                    }
                }
                _ => {}
            },
            Overlay::None => match key.code {
                KeyCode::Esc => return Ok(HomeAction::Quit),
                KeyCode::Tab => overlay = Overlay::Help,
                KeyCode::Char('p') if ctrl => overlay = Overlay::Palette(0),
                KeyCode::Enter => {
                    let typed = input.trim().to_string();
                    if !typed.is_empty() {
                        return Ok(HomeAction::Exec(typed));
                    }
                    if let Some(entry) = chats.get(selected) {
                        return Ok(HomeAction::Open(entry.id.clone()));
                    }
                }
                KeyCode::Backspace => {
                    input.pop();
                }
                KeyCode::Left => {
                    if !chats.is_empty() {
                        selected = (selected + chats.len() - 1) % chats.len();
                    }
                }
                KeyCode::Right => {
                    if !chats.is_empty() {
                        selected = (selected + 1) % chats.len();
                    }
                }
                KeyCode::Char(c) if !ctrl => {
                    input.push(c);
                }
                _ => {}
            },
        }
    }
}

/// Center a fixed-width column in `area`.
pub(crate) fn centered_col(area: Rect, width: u16) -> Rect {
    let w = width.min(area.width);
    Rect {
        x: area.x + (area.width - w) / 2,
        width: w,
        ..area
    }
}

fn draw_home(
    f: &mut ratatui::Frame,
    session: &Session,
    chats: &[ChatEntry],
    online: bool,
    selected: usize,
    input: &str,
    overlay: &Overlay,
) {
    f.render_widget(Block::default().style(Style::default().bg(BG)), f.area());
    // Help and the palette replace the layout; errors and command output
    // render inline on the input box, replacing the prompt line.
    let banner: Option<(&str, bool)> = match overlay {
        Overlay::None => None,
        Overlay::Help => {
            draw_command_box(f, None);
            return;
        }
        Overlay::Palette(cursor) => {
            draw_command_box(f, Some(*cursor));
            return;
        }
        Overlay::Error(msg) => Some((msg.as_str(), true)),
        Overlay::Output(msg) => Some((msg.as_str(), false)),
    };
    let col = centered_col(f.area(), 64);
    if col.width < 20 || f.area().height < 14 {
        return;
    }
    // The banner takes the prompt line inside the input box; grow the box so
    // long or multi-line text wraps instead of truncating.
    let text_w = col.width.saturating_sub(4) as usize;
    let banner_rows = match banner {
        Some((msg, _)) => msg
            .trim_end()
            .lines()
            .map(|l| (l.chars().count().div_ceil(text_w.max(1)) as u16).max(1))
            .sum::<u16>()
            .max(1)
            .min(f.area().height.saturating_sub(9)),
        None => 1,
    };
    // Vertically centered: logo, gap, input box, hints.
    let rows = Layout::vertical([
        Constraint::Length(5),
        Constraint::Length(1),
        Constraint::Length(banner_rows + 3),
        Constraint::Length(1),
    ])
    .flex(Flex::Center)
    .split(col);

    f.render_widget(Paragraph::new(logo_lines()), rows[0]);

    // Input box styled exactly like the chat screen's message box.
    let is_error = matches!(banner, Some((_, true)));
    let input_box = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(if is_error { RED } else { ACCENT }));
    let inner = input_box.inner(rows[2]);
    f.render_widget(input_box, rows[2]);

    // Line 1: the banner, if any, else the pre-written action (or what the
    // user is typing).
    let input_lines: Vec<Line> = if let Some((msg, err)) = banner {
        let color = if err { RED } else { TEXT };
        msg.trim_end()
            .lines()
            .enumerate()
            .map(|(i, l)| {
                if i == 0 && err {
                    Line::from(vec![
                        Span::styled("✗ ", Style::default().fg(RED).add_modifier(Modifier::BOLD)),
                        Span::styled(l.to_string(), Style::default().fg(RED)),
                    ])
                } else {
                    Line::from(Span::styled(l.to_string(), Style::default().fg(color)))
                }
            })
            .collect()
    } else if input.is_empty() {
        let prewritten = match chats.get(selected) {
            Some(c) => {
                let unread = if c.unread > 0 {
                    format!("  ({} unread)", c.unread)
                } else {
                    String::new()
                };
                format!("chat {}{unread} — press enter   ←/→ switch", c.title)
            }
            None => "type `add <friend>` to get started".to_string(),
        };
        vec![Line::from(vec![
            Span::styled(
                "› ",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled(prewritten, Style::default().fg(DIM)),
        ])]
    } else {
        vec![Line::from(vec![
            Span::styled(
                "› ",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled(input.to_string(), Style::default().fg(TEXT)),
        ])]
    };
    // Line 2: account · connection (the server only when it's a deliberate
    // --server/YAPAYAPA_SERVER override, matching the signup form).
    let mut status = vec![Span::styled(
        format!("@{}", session.keystore.profile.username),
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
    )];
    if session.config.server != crate::config::DEFAULT_SERVER {
        let server = session
            .config
            .server
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .to_string();
        status.push(Span::styled(" · ", Style::default().fg(DIM)));
        status.push(Span::styled(server, Style::default().fg(DIM)));
    }
    status.push(Span::styled(" · ", Style::default().fg(DIM)));
    status.push(if online {
        Span::styled("● online", Style::default().fg(GREEN))
    } else {
        Span::styled("○ offline", Style::default().fg(RED))
    });
    let panel_rows =
        Layout::vertical([Constraint::Length(banner_rows), Constraint::Length(1)]).split(inner);
    f.render_widget(
        Paragraph::new(input_lines).wrap(ratatui::widgets::Wrap { trim: true }),
        panel_rows[0],
    );
    f.render_widget(Paragraph::new(Line::from(status)), panel_rows[1]);
    if banner.is_none() {
        let cursor_x = inner.x + 2 + input.chars().count() as u16;
        f.set_cursor_position((cursor_x.min(inner.right().saturating_sub(1)), inner.y));
    }

    // Hints, right-aligned under the box; with a banner showing, only how
    // to dismiss it.
    let hints = if banner.is_some() {
        vec![
            Span::styled(
                "enter",
                Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" exits", Style::default().fg(DIM)),
        ]
    } else {
        vec![
            Span::styled(
                "tab",
                Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" lists  ", Style::default().fg(DIM)),
            Span::styled(
                "ctrl+p",
                Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" commands  ", Style::default().fg(DIM)),
            Span::styled(
                "esc",
                Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" quit", Style::default().fg(DIM)),
        ]
    };
    f.render_widget(Paragraph::new(Line::from(hints)).right_aligned(), rows[3]);
}

/// The command list, centered. With a cursor it is the interactive palette;
/// without one it is the Tab reference (any key closes).
fn draw_command_box(f: &mut ratatui::Frame, cursor: Option<usize>) {
    let height = COMMANDS.len() as u16 + 3;
    let width = 64u16;
    let [area] = Layout::horizontal([Constraint::Length(width)])
        .flex(Flex::Center)
        .areas(f.area());
    let [area] = Layout::vertical([Constraint::Length(height)])
        .flex(Flex::Center)
        .areas(area);
    f.render_widget(Clear, area);
    let title = if cursor.is_some() {
        " commands — ↑/↓ choose, enter run, esc close "
    } else {
        " commands — press any key to close "
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().bg(SURFACE))
        .title(Span::styled(title, Style::default().fg(DIM)));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let mut lines = Vec::new();
    for (i, (name, desc, _)) in COMMANDS.iter().enumerate() {
        let is_sel = cursor == Some(i);
        let name_style = if is_sel {
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(TEXT)
        };
        let mut line = Line::from(vec![
            Span::styled(
                if is_sel { "▌ " } else { "  " },
                Style::default().fg(ACCENT),
            ),
            Span::styled(format!("{name:<16}"), name_style),
            Span::styled((*desc).to_string(), Style::default().fg(DIM)),
        ]);
        if is_sel {
            line = line.style(Style::default().bg(BG));
        }
        lines.push(line);
    }
    f.render_widget(Paragraph::new(lines), inner);
}

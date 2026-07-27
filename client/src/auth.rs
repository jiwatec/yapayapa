//! In-TUI authentication so bare `yapayapa` never sends the user back to
//! the shell: a signup form on first run, a masked password unlock after
//! that, and a best-effort session-token refresh once unlocked.

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Flex, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph, Wrap};
use ratatui::Terminal;

use crate::api::Api;
use crate::config::Config;
use crate::home::{centered_col, logo_lines};
use crate::keystore::KeystoreError;
use crate::session::Session;
use crate::tui::theme::*;
use crate::tui::TermGuard;

/// Produce an unlocked session (plus the password that unlocked it, for
/// re-driving CLI commands), registering or unlocking in the TUI as needed.
/// `None` means the user chose to quit.
pub async fn establish_session(config: &Config) -> anyhow::Result<Option<(Session, String, bool)>> {
    if config.keystore_path().exists() {
        // Scripted runs skip the prompt entirely.
        if let Ok(pw) = std::env::var("YAPAYAPA_PASSWORD") {
            let mut session = Session::unlock_with(config.clone(), &pw)?;
            refresh_token(&mut session, &pw).await;
            let online = session.api.health().await;
            Ok(Some((session, pw, online)))
        } else {
            unlock_screen(config).await
        }
    } else {
        register_screen(config).await
    }
}

/// Re-login with the unlock password so a token that expired since the last
/// run never surfaces as "run `yapayapa login`". Offline or rejected is
/// fine — the session still works locally and per-request errors will show.
async fn refresh_token(session: &mut Session, password: &str) {
    let api = Api::new(&session.config.server, None);
    if let Ok(auth) = api
        .login(&session.keystore.profile.username, password)
        .await
    {
        if session.keystore.set_token(auth.token.clone()).is_ok() {
            session.api = Api::new(&session.config.server, Some(auth.token));
        }
    }
}

fn server_label(config: &Config) -> String {
    config
        .server
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .to_string()
}

fn mask(s: &str) -> String {
    "•".repeat(s.chars().count())
}

/// One labelled input line inside the auth box.
fn field_line(label: &str, value: &str, masked: bool, active: bool) -> Line<'static> {
    let shown = if masked {
        mask(value)
    } else {
        value.to_string()
    };
    Line::from(vec![
        Span::styled(
            if active { "› " } else { "  " },
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{label:<10}"),
            Style::default().fg(if active { TEXT } else { DIM }),
        ),
        Span::styled(shown, Style::default().fg(TEXT)),
    ])
}

fn hint_line(pairs: &[(&'static str, &'static str)]) -> Line<'static> {
    let mut spans = Vec::new();
    for (key, what) in pairs {
        spans.push(Span::styled(
            *key,
            Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(format!(" {what}  "), Style::default().fg(DIM)));
    }
    Line::from(spans)
}

/// Masked password prompt for an existing account. Wrong password stays on
/// the screen with a notice; Esc returns `None`.
async fn unlock_screen(config: &Config) -> anyhow::Result<Option<(Session, String, bool)>> {
    let profile = crate::keystore::Keystore::peek_profile(&config.keystore_path());
    let username = profile.map(|p| p.username).unwrap_or_default();
    let _guard = TermGuard::new()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;
    let mut password = String::new();
    let mut notice: Option<String> = None;
    let mut busy = false;
    // Unlocked but still refreshing the server session; the screen stays up
    // with a "signing in…" status so a slow (cold-start) backend never
    // leaves the user staring at the bare terminal.
    let mut unlocked: Option<Session> = None;

    loop {
        terminal.draw(|f| {
            f.render_widget(Block::default().style(Style::default().bg(BG)), f.area());
            let col = centered_col(f.area(), 64);
            if col.width < 20 || f.area().height < 14 {
                return;
            }
            let rows = Layout::vertical([
                Constraint::Length(5),
                Constraint::Length(1),
                Constraint::Length(4),
                Constraint::Length(1),
            ])
            .flex(Flex::Center)
            .split(col);
            f.render_widget(Paragraph::new(logo_lines()), rows[0]);

            let boxed = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(ACCENT))
                .title(Span::styled(" welcome back ", Style::default().fg(DIM)));
            let inner = boxed.inner(rows[2]);
            f.render_widget(boxed, rows[2]);
            let panel =
                Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(inner);
            f.render_widget(
                Paragraph::new(field_line("password", &password, true, true)),
                panel[0],
            );
            let mut status = vec![Span::styled(
                format!("@{username}"),
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            )];
            if config.server != crate::config::DEFAULT_SERVER {
                status.push(Span::styled(" · ", Style::default().fg(DIM)));
                status.push(Span::styled(server_label(config), Style::default().fg(DIM)));
            }
            if unlocked.is_some() {
                status.push(Span::styled("  signing in…", Style::default().fg(YELLOW)));
            } else if busy {
                status.push(Span::styled("  unlocking…", Style::default().fg(YELLOW)));
            } else if let Some(n) = &notice {
                status.push(Span::styled(format!("  {n}"), Style::default().fg(RED)));
            }
            f.render_widget(Paragraph::new(Line::from(status)), panel[1]);
            let cursor_x = inner.x + 12 + mask(&password).chars().count() as u16;
            f.set_cursor_position((cursor_x.min(inner.right().saturating_sub(1)), inner.y));

            f.render_widget(
                Paragraph::new(hint_line(&[("enter", "unlock"), ("esc", "quit")])).right_aligned(),
                rows[3],
            );
        })?;

        if let Some(mut session) = unlocked.take() {
            // "signing in…" frame is painted; refresh the token and probe
            // connectivity while the screen is still up.
            refresh_token(&mut session, &password).await;
            let online = session.api.health().await;
            return Ok(Some((session, password, online)));
        }

        if busy {
            // Frame with the "unlocking…" notice is painted; do the work.
            match Session::unlock_with(config.clone(), &password) {
                Ok(session) => {
                    unlocked = Some(session);
                    busy = false;
                }
                Err(e) => {
                    notice = Some(match e.downcast_ref::<KeystoreError>() {
                        Some(KeystoreError::WrongPassword) => "wrong password".into(),
                        _ => format!("{e}"),
                    });
                    password.clear();
                    busy = false;
                }
            }
            continue;
        }

        let key = match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => key,
            Event::Resize(_, _) => {
                terminal.clear()?;
                continue;
            }
            _ => continue,
        };
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('c') {
            return Ok(None);
        }
        match key.code {
            KeyCode::Esc => return Ok(None),
            KeyCode::Enter if !password.is_empty() => busy = true,
            KeyCode::Backspace => {
                password.pop();
            }
            KeyCode::Char(c) if !ctrl => {
                password.push(c);
                notice = None;
            }
            _ => {}
        }
    }
}

const FIELDS: [(&str, bool); 3] = [("username", false), ("password", true), ("confirm", true)];

/// First-run signup form: username, password, confirm — then the key-loss
/// notice once the account exists. Esc returns `None`.
async fn register_screen(config: &Config) -> anyhow::Result<Option<(Session, String, bool)>> {
    let _guard = TermGuard::new()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;
    let mut values = [String::new(), String::new(), String::new()];
    let mut active: usize = 0;
    let mut notice: Option<String> = None;
    let mut busy = false;

    loop {
        terminal.draw(|f| {
            f.render_widget(Block::default().style(Style::default().bg(BG)), f.area());
            let col = centered_col(f.area(), 64);
            if col.width < 20 || f.area().height < 16 {
                return;
            }
            let rows = Layout::vertical([
                Constraint::Length(5),
                Constraint::Length(1),
                Constraint::Length(6),
                Constraint::Length(1),
            ])
            .flex(Flex::Center)
            .split(col);
            f.render_widget(Paragraph::new(logo_lines()), rows[0]);

            let boxed = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(ACCENT))
                .title(Span::styled(
                    " create your account ",
                    Style::default().fg(DIM),
                ));
            let inner = boxed.inner(rows[2]);
            f.render_widget(boxed, rows[2]);
            let panel = Layout::vertical([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .split(inner);
            for (i, (label, masked)) in FIELDS.iter().enumerate() {
                f.render_widget(
                    Paragraph::new(field_line(label, &values[i], *masked, active == i)),
                    panel[i],
                );
            }
            // The server only matters when it isn't the built-in default —
            // surface a deliberate --server/YAPAYAPA_SERVER override so a
            // dev doesn't create the account on the wrong backend.
            let mut status = if config.server == crate::config::DEFAULT_SERVER {
                Vec::new()
            } else {
                vec![
                    Span::styled("server ", Style::default().fg(DIM)),
                    Span::styled(server_label(config), Style::default().fg(TEXT)),
                ]
            };
            if busy {
                status.push(Span::styled(
                    "  creating account…",
                    Style::default().fg(YELLOW),
                ));
            } else if let Some(n) = &notice {
                status.push(Span::styled(format!("  {n}"), Style::default().fg(RED)));
            }
            f.render_widget(Paragraph::new(Line::from(status)), panel[3]);
            let shown = if FIELDS[active].1 {
                mask(&values[active])
            } else {
                values[active].clone()
            };
            let cursor_x = inner.x + 12 + shown.chars().count() as u16;
            f.set_cursor_position((
                cursor_x.min(inner.right().saturating_sub(1)),
                inner.y + active as u16,
            ));

            f.render_widget(
                Paragraph::new(hint_line(&[
                    ("enter", "next / create"),
                    ("tab", "switch"),
                    ("esc", "quit"),
                ]))
                .right_aligned(),
                rows[3],
            );
        })?;

        if busy {
            if values[1] != values[2] {
                notice = Some("passwords do not match".into());
                values[2].clear();
                active = 2;
                busy = false;
                continue;
            }
            match crate::commands::register_account(config, &values[0], &values[1]).await {
                Ok(keystore) => {
                    key_loss_screen(&mut terminal, &keystore)?;
                    let session = Session::unlock_with(config.clone(), &values[1])?;
                    // Registration just round-tripped the server: online.
                    return Ok(Some((session, std::mem::take(&mut values[1]), true)));
                }
                Err(e) => {
                    notice = Some(format!("{e:#}"));
                    busy = false;
                }
            }
            continue;
        }

        let key = match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => key,
            Event::Resize(_, _) => {
                terminal.clear()?;
                continue;
            }
            _ => continue,
        };
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('c') {
            return Ok(None);
        }
        match key.code {
            KeyCode::Esc => return Ok(None),
            KeyCode::Tab | KeyCode::Down => active = (active + 1) % FIELDS.len(),
            KeyCode::BackTab | KeyCode::Up => active = (active + FIELDS.len() - 1) % FIELDS.len(),
            KeyCode::Enter => {
                if active + 1 < FIELDS.len() {
                    active += 1;
                } else if values.iter().all(|v| !v.is_empty()) {
                    busy = true;
                } else {
                    notice = Some("fill in every field".into());
                }
            }
            KeyCode::Backspace => {
                values[active].pop();
            }
            KeyCode::Char(c) if !ctrl => {
                values[active].push(c);
                notice = None;
            }
            _ => {}
        }
    }
}

/// Post-signup screen: identity details plus the unrecoverable-keys warning.
fn key_loss_screen(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    keystore: &crate::keystore::Keystore,
) -> anyhow::Result<()> {
    let fingerprint = keystore
        .identity
        .public()
        .fingerprint()
        .unwrap_or_else(|_| "unavailable".into());
    loop {
        terminal.draw(|f| {
            f.render_widget(Block::default().style(Style::default().bg(BG)), f.area());
            let col = centered_col(f.area(), 64);
            if col.width < 20 || f.area().height < 16 {
                return;
            }
            let rows = Layout::vertical([
                Constraint::Length(5),
                Constraint::Length(1),
                Constraint::Length(12),
            ])
            .flex(Flex::Center)
            .split(col);
            f.render_widget(Paragraph::new(logo_lines()), rows[0]);
            let boxed = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(BORDER))
                .title(Span::styled(" you're in ", Style::default().fg(DIM)));
            let inner = boxed.inner(rows[2]);
            f.render_widget(boxed, rows[2]);
            let mut lines = vec![
                Line::from(vec![
                    Span::styled("registered as ", Style::default().fg(DIM)),
                    Span::styled(
                        format!("@{}", keystore.profile.username),
                        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("public ID   ", Style::default().fg(DIM)),
                    Span::styled(
                        keystore.profile.public_id.clone(),
                        Style::default().fg(TEXT),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("fingerprint ", Style::default().fg(DIM)),
                    Span::styled(fingerprint.clone(), Style::default().fg(TEXT)),
                ]),
                Line::default(),
            ];
            // Reflowed to the box width by `Wrap` below.
            lines.push(Line::from(Span::styled(
                crate::commands::KEY_LOSS_WARNING.replace('\n', " "),
                Style::default().fg(YELLOW),
            )));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "press any key to start chatting",
                Style::default().fg(DIM),
            )));
            f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        })?;
        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => return Ok(()),
            Event::Resize(_, _) => terminal.clear()?,
            _ => {}
        }
    }
}

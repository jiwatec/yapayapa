//! YapaYapa — terminal-first, offline-first encrypted messaging client.

mod api;
mod attach;
mod auth;
mod chat;
mod commands;
mod config;
mod groups;
mod home;
mod keystore;
mod lan;
mod messaging;
mod session;
mod store;
mod tui;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use uuid::Uuid;

use crate::chat::ChatTarget;
use crate::config::Config;
use crate::session::Session;

#[derive(Parser)]
#[command(
    name = "yapayapa",
    version,
    about = "Terminal-first, offline-first encrypted messaging"
)]
struct Cli {
    /// Backend base URL (or YAPAYAPA_SERVER).
    #[arg(long, global = true)]
    server: Option<String>,
    /// Data directory for this account (or YAPAYAPA_DATA_DIR). Use one
    /// directory per account.
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    /// With no command, opens the home screen.
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create an account and a local encrypted keystore.
    Register { username: Option<String> },
    /// Refresh the session token for the account in this data directory.
    Login { username: Option<String> },
    /// Invalidate the server session and clear the local token.
    Logout,
    /// Show your profile (username, public ID, fingerprint).
    Profile,
    /// Show your identity fingerprint and public keys.
    Identity,
    /// Compare fingerprints with a contact and mark them verified.
    Verify { user: String },
    /// Contact management.
    Contacts {
        #[command(subcommand)]
        cmd: ContactsCmd,
    },
    /// Open a chat with a contact (username or public ID) or a group id.
    Chat {
        target: String,
        /// Use the simple line-based CLI instead of the full-screen UI.
        #[arg(long)]
        plain: bool,
        /// Deprecated: the full-screen UI is now the default.
        #[arg(long, hide = true)]
        tui: bool,
    },
    /// Show connection, outbox, and unread status.
    Status,
    /// Encrypted local outbox.
    Outbox {
        #[command(subcommand)]
        cmd: OutboxCmd,
    },
    /// LAN peers (optional local-network transport).
    Peers {
        #[command(subcommand)]
        cmd: PeersCmd,
    },
    /// Group chats (up to 20 members).
    Groups {
        #[command(subcommand)]
        cmd: GroupsCmd,
    },
    /// Encrypt and send an image (PNG/JPEG/WebP) to a contact or group.
    SendImage {
        path: String,
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        group: Option<Uuid>,
    },
    /// Encrypted attachments.
    Attachments {
        #[command(subcommand)]
        cmd: AttachmentsCmd,
    },
    /// Decrypt (if needed) and open an image with the system viewer.
    OpenImage { message_id: Uuid },
    /// Add a contact by username or public ID (short for `contacts add`).
    Add {
        user: String,
        /// Accept a changed identity key (after out-of-band verification!).
        #[arg(long)]
        accept_new_key: bool,
    },
    /// List your contacts (short for `contacts list`).
    Friends,
    /// Look up a user on the server (short for `contacts search`).
    Find { user: String },
    /// Send queued messages now (short for `outbox retry`).
    Sync,
    /// Create a group chat (short for `groups create`).
    Group { name: String },
    /// Send an image to a contact or group (short for `send-image`).
    Img { to: String, path: String },
}

#[derive(Subcommand)]
enum ContactsCmd {
    /// Look up a user on the server without adding them.
    Search { user: String },
    /// Add a contact by username or public ID.
    Add {
        user: String,
        /// Accept a changed identity key (after out-of-band verification!).
        #[arg(long)]
        accept_new_key: bool,
    },
    /// List local contacts.
    List,
}

#[derive(Subcommand)]
enum OutboxCmd {
    /// Show queued, not-yet-confirmed envelopes.
    List,
    /// Try to flush the outbox through the relay now.
    Retry,
}

#[derive(Subcommand)]
enum PeersCmd {
    /// Discover YapaYapa peers on the local network (mDNS).
    List,
    /// Exchange queued messages directly with a discovered peer.
    Connect { peer: String },
}

#[derive(Subcommand)]
enum GroupsCmd {
    Create {
        name: String,
    },
    List,
    Info {
        group_id: Uuid,
    },
    AddMember {
        group_id: Uuid,
        user: String,
    },
    RemoveMember {
        group_id: Uuid,
        user: String,
    },
    /// Open a group chat.
    Chat {
        group_id: Uuid,
        /// Use the simple line-based CLI instead of the full-screen UI.
        #[arg(long)]
        plain: bool,
        /// Deprecated: the full-screen UI is now the default.
        #[arg(long, hide = true)]
        tui: bool,
    },
}

#[derive(Subcommand)]
enum AttachmentsCmd {
    List,
    Download { attachment_id: Uuid },
}

async fn open_chat(config: Config, target: &str, use_tui: bool) -> anyhow::Result<()> {
    let session = Session::load(config)?;
    // A UUID selector that matches a known group opens the group chat;
    // otherwise treat the selector as a contact.
    let target = if let Ok(gid) = target.parse::<Uuid>() {
        if let Some(name) = session.store.group_name(gid)? {
            ChatTarget::Group(gid, name)
        } else {
            let contact = commands::resolve_contact(&session, target, false).await?;
            ChatTarget::Direct(contact)
        }
    } else {
        let contact = commands::resolve_contact(&session, target, false).await?;
        ChatTarget::Direct(contact)
    };
    if use_tui {
        tui::run(&session, target).await
    } else {
        chat::run_chat(&session, target).await
    }
}

async fn open_group_chat(config: Config, group_id: Uuid, use_tui: bool) -> anyhow::Result<()> {
    let session = Session::load(config)?;
    let name = match session.store.group_name(group_id)? {
        Some(n) => n,
        None => {
            let info = session
                .api
                .group_info(group_id)
                .await
                .map_err(|e| anyhow::anyhow!("unknown group: {e}"))?;
            groups::cache_group(&session, &info)?;
            info.name
        }
    };
    let target = ChatTarget::Group(group_id, name);
    if use_tui {
        tui::run(&session, target).await
    } else {
        chat::run_chat(&session, target).await
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let config = Config::resolve(cli.server.clone(), cli.data_dir.clone());
    if let Err(e) = run(cli, config).await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli, config: Config) -> anyhow::Result<()> {
    let Some(cmd) = cli.cmd else {
        return home::run(config).await;
    };
    match cmd {
        Cmd::Register { username } => commands::register(config, username).await,
        Cmd::Login { username } => commands::login(config, username).await,
        Cmd::Logout => commands::logout(config).await,
        Cmd::Profile => commands::profile(config).await,
        Cmd::Identity => commands::identity(config).await,
        Cmd::Verify { user } => commands::verify(config, user).await,
        Cmd::Contacts { cmd } => match cmd {
            ContactsCmd::Search { user } => commands::contacts_search(config, user).await,
            ContactsCmd::Add {
                user,
                accept_new_key,
            } => commands::contacts_add(config, user, accept_new_key).await,
            ContactsCmd::List => commands::contacts_list(config).await,
        },
        Cmd::Chat { target, plain, .. } => open_chat(config, &target, !plain).await,
        Cmd::Status => commands::status(config).await,
        Cmd::Outbox { cmd } => match cmd {
            OutboxCmd::List => commands::outbox_list(config).await,
            OutboxCmd::Retry => commands::outbox_retry(config).await,
        },
        Cmd::Peers { cmd } => match cmd {
            PeersCmd::List => lan::peers_list(config).await,
            PeersCmd::Connect { peer } => lan::peers_connect(config, peer).await,
        },
        Cmd::Groups { cmd } => match cmd {
            GroupsCmd::Create { name } => commands::groups_create(config, name).await,
            GroupsCmd::List => commands::groups_list(config).await,
            GroupsCmd::Info { group_id } => commands::groups_info(config, group_id).await,
            GroupsCmd::AddMember { group_id, user } => {
                commands::groups_add_member(config, group_id, user).await
            }
            GroupsCmd::RemoveMember { group_id, user } => {
                commands::groups_remove_member(config, group_id, user).await
            }
            GroupsCmd::Chat {
                group_id, plain, ..
            } => open_group_chat(config, group_id, !plain).await,
        },
        Cmd::SendImage { path, to, group } => commands::send_image(config, path, to, group).await,
        Cmd::Attachments { cmd } => match cmd {
            AttachmentsCmd::List => commands::attachments_list(config).await,
            AttachmentsCmd::Download { attachment_id } => {
                commands::attachments_download(config, attachment_id).await
            }
        },
        Cmd::OpenImage { message_id } => commands::open_image(config, message_id).await,
        // Short aliases for the most common actions.
        Cmd::Add {
            user,
            accept_new_key,
        } => commands::contacts_add(config, user, accept_new_key).await,
        Cmd::Friends => commands::contacts_list(config).await,
        Cmd::Find { user } => commands::contacts_search(config, user).await,
        Cmd::Sync => commands::outbox_retry(config).await,
        Cmd::Group { name } => commands::groups_create(config, name).await,
        Cmd::Img { to, path } => {
            // A UUID target means a group; anything else is a contact.
            match to.parse::<Uuid>() {
                Ok(gid) => commands::send_image(config, path, None, Some(gid)).await,
                Err(_) => commands::send_image(config, path, Some(to), None).await,
            }
        }
    }
}

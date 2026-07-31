//! Implementations of the non-chat CLI commands.

use std::io::Write as _;
use std::path::Path;

use uuid::Uuid;
use yapayapa_common::crypto::Identity;
use yapayapa_common::validate;

use crate::api::Api;
use crate::attach;
use crate::config::Config;
use crate::groups;
use crate::keystore::{read_password, Keystore, Profile};
use crate::messaging::sync_once;
use crate::session::Session;
use crate::store::{Contact, LocalStore};

pub const KEY_LOSS_WARNING: &str = "\
IMPORTANT: your private encryption keys exist ONLY on this machine, inside\n\
your encrypted keystore. If you lose this directory or forget your password,\n\
your identity and message history are unrecoverable — the server cannot help,\n\
because it never sees your keys. Back up your data directory safely.";

fn read_line(prompt: &str) -> anyhow::Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

/// Create the account on the server and the local keystore/store. Shared by
/// the CLI command and the in-TUI signup form.
pub async fn register_account(
    config: &Config,
    username: &str,
    password: &str,
) -> anyhow::Result<Keystore> {
    if config.keystore_path().exists() {
        let existing = Keystore::peek_profile(&config.keystore_path());
        anyhow::bail!(
            "an account ({}) already exists in {} — use a different --data-dir for a second account",
            existing.map(|p| p.username).unwrap_or_default(),
            config.data_dir.display()
        );
    }
    let normalized = validate::normalize_username(username);
    validate::validate_username(&normalized).map_err(|e| anyhow::anyhow!(e))?;
    validate::validate_password(password).map_err(|e| anyhow::anyhow!(e))?;

    // Identity keys are generated locally and never leave this machine —
    // only the public halves are registered.
    let identity = Identity::generate();
    let api = Api::new(&config.server, None);
    let auth = api
        .register(&normalized, password, &identity.public())
        .await
        .map_err(|e| anyhow::anyhow!("registration failed: {e}"))?;

    config.ensure_dirs()?;
    let keystore = Keystore::create(
        &config.keystore_path(),
        password,
        Profile {
            user_id: auth.user.user_id,
            public_id: auth.user.public_id.clone(),
            username: auth.user.username.clone(),
            server: config.server.clone(),
        },
        identity,
        auth.token,
    )?;
    // Initialize local storage now so offline mode works immediately.
    LocalStore::open(&config.db_path(), &keystore.master_key)?;
    Ok(keystore)
}

pub async fn register(config: Config, username: Option<String>) -> anyhow::Result<()> {
    // Show the rules up front so people don't hit them only after a failed try.
    println!(
        "Username: {}-{} characters, a-z 0-9 _ , must start with a letter.",
        validate::USERNAME_MIN,
        validate::USERNAME_MAX
    );
    println!(
        "Password: at least {} characters.",
        validate::PASSWORD_MIN
    );
    let username = match username {
        Some(u) => u,
        None => read_line("Username: ")?,
    };
    let password = read_password("Password (also protects your local keys): ")?;
    if std::env::var("YAPAYAPA_PASSWORD").is_err() {
        let confirm = read_password("Confirm password: ")?;
        if password != confirm {
            anyhow::bail!("passwords do not match");
        }
    }
    let keystore = register_account(&config, &username, &password).await?;

    println!("registered as @{}", keystore.profile.username);
    println!("public ID:   {}", keystore.profile.public_id);
    println!(
        "fingerprint: {}",
        keystore
            .identity
            .public()
            .fingerprint()
            .map_err(|e| anyhow::anyhow!("{e}"))?
    );
    println!("\n{KEY_LOSS_WARNING}");
    Ok(())
}

pub async fn login(config: Config, username: Option<String>) -> anyhow::Result<()> {
    let path = config.keystore_path();
    if !path.exists() {
        anyhow::bail!(
            "no local keystore found in {}.\n\
             In this MVP your private keys live only where you registered; logging in on a\n\
             new machine would create an account that cannot decrypt your history.\n\
             If this is the right machine, check --data-dir / YAPAYAPA_DATA_DIR.",
            config.data_dir.display()
        );
    }
    let password = read_password("Password: ")?;
    let mut keystore = Keystore::unlock(&path, &password)?;
    if let Some(username) = username {
        if validate::normalize_username(&username) != keystore.profile.username {
            anyhow::bail!(
                "this keystore belongs to @{} — use a separate --data-dir per account",
                keystore.profile.username
            );
        }
    }
    let api = Api::new(&config.server, None);
    let auth = api
        .login(&keystore.profile.username, &password)
        .await
        .map_err(|e| anyhow::anyhow!("login failed: {e}"))?;
    keystore.set_token(auth.token)?;
    println!("logged in as @{}", keystore.profile.username);
    Ok(())
}

pub async fn logout(config: Config) -> anyhow::Result<()> {
    let mut session = Session::load(config)?;
    if let Err(e) = session.api.logout().await {
        println!("(server logout skipped: {e})");
    }
    session.keystore.set_token(String::new())?;
    println!("logged out — local session token cleared");
    Ok(())
}

pub async fn profile(config: Config) -> anyhow::Result<()> {
    let session = Session::load(config)?;
    let p = &session.keystore.profile;
    println!("username:    @{}", p.username);
    println!("public ID:   {}", p.public_id);
    println!("user UUID:   {}", p.user_id);
    println!("server:      {}", p.server);
    println!(
        "fingerprint: {}",
        session
            .keystore
            .identity
            .public()
            .fingerprint()
            .map_err(|e| anyhow::anyhow!("{e}"))?
    );
    Ok(())
}

pub async fn identity(config: Config) -> anyhow::Result<()> {
    let session = Session::load(config)?;
    let public = session.keystore.identity.public();
    println!(
        "your identity fingerprint:\n  {}",
        public.fingerprint().map_err(|e| anyhow::anyhow!("{e}"))?
    );
    println!("\nshare this with contacts over a trusted channel (in person, a call)");
    println!(
        "so they can run `yapayapa verify {}`.",
        session.keystore.profile.username
    );
    println!("\npublic signing key: {}", public.sign_pub);
    println!("public DH key:      {}", public.dh_pub);
    println!("\n{KEY_LOSS_WARNING}");
    Ok(())
}

/// Resolve a contact: local store first; if unknown and online, fetch + pin.
pub async fn resolve_contact(
    session: &Session,
    selector: &str,
    accept_new_key: bool,
) -> anyhow::Result<Contact> {
    if let Some(c) = session.store.contact_by_selector(selector)? {
        return Ok(c);
    }
    let user = session.api.lookup(selector).await.map_err(|e| {
        anyhow::anyhow!("'{selector}' is not a local contact and lookup failed: {e}")
    })?;
    user.identity
        .verify_prekey()
        .map_err(|_| anyhow::anyhow!("server returned an identity that fails verification"))?;
    session.store.upsert_contact(&user, accept_new_key)?;
    session
        .store
        .contact_by_id(user.user_id)?
        .ok_or_else(|| anyhow::anyhow!("contact vanished"))
}

pub async fn verify(config: Config, selector: String) -> anyhow::Result<()> {
    let session = Session::load(config)?;
    let contact = resolve_contact(&session, &selector, false).await?;
    let mine = session
        .keystore
        .identity
        .public()
        .fingerprint()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let theirs = contact
        .identity
        .fingerprint()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("your fingerprint:          {mine}");
    println!("@{}'s fingerprint: {theirs}", contact.username);
    println!(
        "\nCompare @{}'s fingerprint over a TRUSTED channel (in person or a call).",
        contact.username
    );
    let answer = read_line("Does it match exactly? [y/N] ")?;
    if answer.eq_ignore_ascii_case("y") {
        session.store.set_verified(contact.user_id, true)?;
        println!("✓ @{} marked as verified", contact.username);
    } else {
        session.store.set_verified(contact.user_id, false)?;
        println!(
            "@{} left unverified — do NOT trust this identity yet",
            contact.username
        );
    }
    Ok(())
}

pub async fn contacts_search(config: Config, selector: String) -> anyhow::Result<()> {
    let session = Session::load(config)?;
    let user = session
        .api
        .lookup(&selector)
        .await
        .map_err(|e| anyhow::anyhow!("lookup failed: {e}"))?;
    println!("@{}", user.username);
    println!("  public ID:   {}", user.public_id);
    println!(
        "  fingerprint: {}",
        user.identity
            .fingerprint()
            .map_err(|e| anyhow::anyhow!("{e}"))?
    );
    Ok(())
}

pub async fn contacts_add(
    config: Config,
    selector: String,
    accept_new_key: bool,
) -> anyhow::Result<()> {
    let session = Session::load(config)?;
    let user = session
        .api
        .lookup(&selector)
        .await
        .map_err(|e| anyhow::anyhow!("lookup failed: {e}"))?;
    user.identity
        .verify_prekey()
        .map_err(|_| anyhow::anyhow!("server returned an identity that fails verification"))?;
    session.store.upsert_contact(&user, accept_new_key)?;
    let _ = session.api.add_contact(&selector).await; // server-side list is best-effort
    println!("added @{} ({})", user.username, user.public_id);
    println!(
        "fingerprint: {}",
        user.identity
            .fingerprint()
            .map_err(|e| anyhow::anyhow!("{e}"))?
    );
    println!(
        "run `yapayapa verify {}` after comparing fingerprints out of band.",
        user.username
    );
    Ok(())
}

pub async fn contacts_list(config: Config) -> anyhow::Result<()> {
    let session = Session::load(config)?;
    // Offline-first: the local pinned store is the source of truth, but when
    // online, pull the server-side contact list to pick up entries added
    // from another session. Key pinning still applies (no silent changes).
    if let Ok(server_contacts) = session.api.list_contacts().await {
        for entry in server_contacts {
            if session.store.contact_by_id(entry.user.user_id)?.is_none() {
                entry
                    .user
                    .identity
                    .verify_prekey()
                    .map_err(|_| anyhow::anyhow!("server returned an invalid identity"))?;
                session.store.upsert_contact(&entry.user, false)?;
            }
        }
    }
    let contacts = session.store.list_contacts()?;
    if contacts.is_empty() {
        println!("no contacts yet — add one with `yapayapa contacts add <username-or-public-id>`");
        return Ok(());
    }
    for c in contacts {
        let unread = session.store.unread_count(&c.user_id.to_string())?;
        println!(
            "@{:<20} {} {}{}",
            c.username,
            c.public_id,
            if c.verified {
                "[verified]"
            } else {
                "[unverified]"
            },
            if unread > 0 {
                format!(" ({unread} unread)")
            } else {
                String::new()
            }
        );
    }
    Ok(())
}

pub async fn status(config: Config) -> anyhow::Result<()> {
    let session = Session::load(config)?;
    println!(
        "account:  @{} ({})",
        session.keystore.profile.username, session.keystore.profile.public_id
    );
    println!("server:   {}", session.config.server);
    let online = session.api.health().await;
    println!(
        "network:  {}",
        if online {
            "online (relay reachable)"
        } else {
            "OFFLINE (relay unreachable)"
        }
    );
    if online {
        match session.api.me().await {
            Ok(_) => println!("session:  valid"),
            Err(_) => println!("session:  EXPIRED — run `yapayapa login` to refresh"),
        }
    }
    let outbox = session.store.outbox_list()?;
    println!("outbox:   {} queued envelope(s)", outbox.len());
    // Sync whenever we're online: flush any queued envelopes AND drain
    // messages the relay is holding for us, even if our own outbox is empty.
    if online {
        let (flushed, received) = sync_once(&session).await?;
        println!("synced:   flushed {flushed}, received {received}");
    }
    let contacts = session.store.list_contacts()?;
    let mut unread = 0;
    for c in &contacts {
        unread += session.store.unread_count(&c.user_id.to_string())?;
    }
    for (gid, _, _) in session.store.list_groups()? {
        unread += session.store.unread_count(&gid.to_string())?;
    }
    println!("unread:   {unread} message(s)");
    Ok(())
}

pub async fn outbox_list(config: Config) -> anyhow::Result<()> {
    let session = Session::load(config)?;
    let entries = session.store.outbox_list()?;
    if entries.is_empty() {
        println!("outbox is empty");
        return Ok(());
    }
    for e in entries {
        let to = session
            .store
            .contact_by_id(e.recipient_id)?
            .map(|c| format!("@{}", c.username))
            .unwrap_or_else(|| e.recipient_id.to_string());
        println!(
            "{}  to {}  {}  {}",
            e.message_id,
            to,
            e.sent_at.format("%Y-%m-%d %H:%M"),
            e.group_id
                .map(|g| format!("(group {g})"))
                .unwrap_or_default()
        );
    }
    Ok(())
}

pub async fn outbox_retry(config: Config) -> anyhow::Result<()> {
    let session = Session::load(config)?;
    match sync_once(&session).await {
        Ok((flushed, received)) => {
            println!("flushed {flushed} queued envelope(s), received {received} message(s)");
            let left = session.store.outbox_list()?.len();
            if left > 0 {
                println!("{left} envelope(s) still queued (not yet confirmed by the relay)");
            }
            Ok(())
        }
        Err(e) => {
            println!("{e}");
            println!("messages remain safely queued in the encrypted outbox.");
            Ok(())
        }
    }
}

// -- groups ----------------------------------------------------------------

pub async fn groups_create(config: Config, name: String) -> anyhow::Result<()> {
    let session = Session::load(config)?;
    let info = session
        .api
        .create_group(&name)
        .await
        .map_err(|e| anyhow::anyhow!("create failed: {e}"))?;
    groups::rotate_group_key(&session, &info)?;
    println!("created group '{}' ({})", info.name, info.group_id);
    println!(
        "add members with `yapayapa groups add-member {} <user>`",
        info.group_id
    );
    Ok(())
}

pub async fn groups_list(config: Config) -> anyhow::Result<()> {
    let session = Session::load(config)?;
    match session.api.list_groups().await {
        Ok(list) => {
            if list.is_empty() {
                println!("no groups yet");
            }
            for info in &list {
                groups::cache_group(&session, info)?;
                println!(
                    "{}  '{}'  {} member(s), epoch {}",
                    info.group_id,
                    info.name,
                    info.members.len(),
                    info.key_epoch
                );
            }
        }
        Err(_) => {
            println!("(offline — showing cached groups)");
            for (gid, name, epoch) in session.store.list_groups()? {
                println!("{gid}  '{name}'  epoch {epoch}");
            }
        }
    }
    Ok(())
}

pub async fn groups_info(config: Config, group_id: Uuid) -> anyhow::Result<()> {
    let session = Session::load(config)?;
    let info = session
        .api
        .group_info(group_id)
        .await
        .map_err(|e| anyhow::anyhow!("cannot fetch group: {e}"))?;
    groups::cache_group(&session, &info)?;
    println!("group:   '{}'", info.name);
    println!("id:      {}", info.group_id);
    println!("epoch:   {}", info.key_epoch);
    println!(
        "members ({} / {}):",
        info.members.len(),
        yapayapa_common::types::MAX_GROUP_MEMBERS
    );
    for m in &info.members {
        println!("  @{:<20} {:?}", m.user.username, m.role);
    }
    Ok(())
}

pub async fn groups_add_member(config: Config, group_id: Uuid, user: String) -> anyhow::Result<()> {
    let session = Session::load(config)?;
    let info = session
        .api
        .add_group_member(group_id, &user)
        .await
        .map_err(|e| anyhow::anyhow!("add failed: {e}"))?;
    let queued = groups::rotate_group_key(&session, &info)?;
    let (flushed, _) = sync_once(&session).await.unwrap_or((0, 0));
    println!(
        "added {user}; rotated group key to epoch {} ({queued} key message(s) queued, {flushed} sent)",
        info.key_epoch
    );
    Ok(())
}

pub async fn groups_remove_member(
    config: Config,
    group_id: Uuid,
    user: String,
) -> anyhow::Result<()> {
    let session = Session::load(config)?;
    let info = session
        .api
        .remove_group_member(group_id, &user)
        .await
        .map_err(|e| anyhow::anyhow!("remove failed: {e}"))?;
    let queued = groups::rotate_group_key(&session, &info)?;
    let (flushed, _) = sync_once(&session).await.unwrap_or((0, 0));
    println!(
        "removed {user}; rotated group key to epoch {} ({queued} key message(s) queued, {flushed} sent)",
        info.key_epoch
    );
    Ok(())
}

// -- attachments -------------------------------------------------------------

pub async fn send_image(
    config: Config,
    path: String,
    to: Option<String>,
    group: Option<Uuid>,
) -> anyhow::Result<()> {
    let session = Session::load(config)?;
    let path = Path::new(&path);
    match (to, group) {
        (Some(selector), None) => {
            let contact = resolve_contact(&session, &selector, false).await?;
            let content = attach::encrypt_and_upload(&session, path, &[contact.user_id]).await?;
            let wire = crate::messaging::compose_direct(&session, &contact, &content)?;
            crate::messaging::store_outgoing_attachment(&session, wire.message_id, &content)?;
            let (flushed, _) = sync_once(&session).await.unwrap_or((0, 0));
            println!(
                "encrypted image queued for @{}{}",
                contact.username,
                if flushed > 0 {
                    " and sent"
                } else {
                    " (offline — will send later)"
                }
            );
        }
        (None, Some(group_id)) => {
            groups::ensure_current_key(&session, group_id).await?;
            let me = session.keystore.profile.user_id;
            let members: Vec<Uuid> = session
                .store
                .cached_group_members(group_id)?
                .into_iter()
                .filter(|m| *m != me)
                .collect();
            if members.is_empty() {
                anyhow::bail!("group has no other members");
            }
            let content = attach::encrypt_and_upload(&session, path, &members).await?;
            let history_id = groups::compose_group(&session, group_id, &content)?;
            crate::messaging::store_outgoing_attachment(&session, history_id, &content)?;
            let (flushed, _) = sync_once(&session).await.unwrap_or((0, 0));
            println!("encrypted image queued for the group ({flushed} envelope(s) sent)");
        }
        _ => anyhow::bail!("specify exactly one of --to <user> or --group <group-id>"),
    }
    Ok(())
}

pub async fn attachments_list(config: Config) -> anyhow::Result<()> {
    let session = Session::load(config)?;
    let list = session.store.list_attachments()?;
    if list.is_empty() {
        println!("no attachments yet");
        return Ok(());
    }
    for (info, path) in list {
        println!(
            "{}  {}  {} KiB  {}",
            info.attachment_id,
            info.filename,
            info.size / 1024,
            path.map(|p| format!("→ {p}"))
                .unwrap_or_else(|| "(not downloaded)".into())
        );
    }
    Ok(())
}

pub async fn attachments_download(config: Config, attachment_id: Uuid) -> anyhow::Result<()> {
    let session = Session::load(config)?;
    let Some((info, _)) = session.store.attachment(attachment_id)? else {
        anyhow::bail!(
            "unknown attachment — the key arrives inside the chat message that referenced it"
        );
    };
    let path = attach::download_and_decrypt(&session, &info).await?;
    println!("decrypted and saved to {}", path.display());
    Ok(())
}

pub async fn open_image(config: Config, message_id: Uuid) -> anyhow::Result<()> {
    let session = Session::load(config)?;
    let Some(info) = session.store.attachment_for_message(message_id)? else {
        anyhow::bail!("that message has no attachment");
    };
    let (_, path) = session
        .store
        .attachment(info.attachment_id)?
        .ok_or_else(|| anyhow::anyhow!("attachment metadata missing"))?;
    let path = match path {
        Some(p) if Path::new(&p).exists() => p,
        _ => {
            let p = attach::download_and_decrypt(&session, &info).await?;
            p.to_string_lossy().to_string()
        }
    };
    println!("opening {path} with the system image viewer…");
    open::that_detached(&path)?;
    Ok(())
}

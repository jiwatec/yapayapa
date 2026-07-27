//! Optional local-network transport: mDNS discovery plus a direct,
//! mutually-authenticated TCP exchange of the same sealed envelopes used on
//! the relay path. No plaintext and no long-term key material crosses the
//! LAN; discovery advertises only a pseudonymous peer ID (a BLAKE3 hash of
//! the public ID) and a port. See docs/THREAT_MODEL.md for what an observer
//! on the LAN can still learn (presence, traffic timing).
//!
//! Security model: a peer must already be a *local contact* (pinned
//! identity). Both sides prove control of their Ed25519 identity key by
//! signing the other side's random challenge before any message frame is
//! accepted. Message contents remain end-to-end sealed envelopes, exactly as
//! on the relay path — LAN never downgrades encryption.

use std::net::SocketAddr;
use std::time::Duration;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;
use yapayapa_common::crypto::{b64, b64_arr, b64_vec, PublicIdentity};
use yapayapa_common::types::WireMessage;

use crate::config::Config;
use crate::messaging::{handle_incoming, Incoming};
use crate::session::Session;
use crate::store::{Contact, LocalState};

const SERVICE_TYPE: &str = "_yapayapa._tcp.local.";
const LAN_AUTH_DOMAIN: &[u8] = b"yapayapa-lan-auth-v1";
const MAX_FRAME: u32 = 128 * 1024;

/// Pseudonymous LAN peer id: hex-truncated keyed BLAKE3 of the public ID.
/// Anyone who already knows your public ID can recognize you; others see
/// only an opaque token.
pub fn peer_id_for(public_id: &str) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("yapayapa lan peer id v1");
    hasher.update(public_id.as_bytes());
    hasher.finalize().to_hex()[..16].to_string()
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum LanFrame {
    Hello {
        public_id: String,
        identity: PublicIdentity,
        /// base64 32-byte random challenge.
        nonce: String,
    },
    /// Signature over LAN_AUTH_DOMAIN || peer_nonce || own_public_id.
    Auth {
        sig: String,
    },
    Msg {
        message: WireMessage,
    },
    Ack {
        message_id: Uuid,
    },
    Bye,
}

async fn write_frame(stream: &mut TcpStream, frame: &LanFrame) -> anyhow::Result<()> {
    let data = serde_json::to_vec(frame)?;
    stream.write_all(&(data.len() as u32).to_be_bytes()).await?;
    stream.write_all(&data).await?;
    Ok(())
}

async fn read_frame(stream: &mut TcpStream) -> anyhow::Result<LanFrame> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME {
        anyhow::bail!("oversized LAN frame");
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

struct Discovered {
    peer_id: String,
    addr: SocketAddr,
}

/// Browse the LAN for peers for `secs` seconds. Optionally also advertise
/// ourselves on `advertise_port`.
async fn browse(
    session: &Session,
    secs: u64,
    advertise_port: Option<u16>,
) -> anyhow::Result<Vec<Discovered>> {
    let daemon = ServiceDaemon::new()?;
    let my_peer_id = peer_id_for(&session.keystore.profile.public_id);

    if let Some(port) = advertise_port {
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            &my_peer_id,
            &format!("{my_peer_id}.local."),
            "",
            port,
            None,
        )?
        .enable_addr_auto();
        daemon.register(info)?;
    }

    let receiver = daemon.browse(SERVICE_TYPE)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    let mut found: Vec<Discovered> = Vec::new();
    loop {
        let timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
        if timeout.is_zero() {
            break;
        }
        let event = tokio::task::block_in_place(|| receiver.recv_timeout(timeout));
        match event {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                let peer_id = info
                    .get_fullname()
                    .split('.')
                    .next()
                    .unwrap_or_default()
                    .to_string();
                if peer_id == my_peer_id {
                    continue;
                }
                // IPv4 only for the MVP; loopback stays eligible so two
                // clients on one machine can test the LAN path.
                if let Some(ip) = info.get_addresses().iter().find(|ip| ip.is_ipv4()) {
                    if !found.iter().any(|d| d.peer_id == peer_id) {
                        found.push(Discovered {
                            peer_id,
                            addr: SocketAddr::new(*ip, info.get_port()),
                        });
                    }
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let _ = daemon.shutdown();
    Ok(found)
}

pub async fn peers_list(config: Config) -> anyhow::Result<()> {
    let session = Session::load(config)?;
    println!("browsing the local network for YapaYapa peers (5s)…");
    println!("(peer IDs are pseudonymous hashes; your contacts' IDs are recognizable below)");
    let peers = browse(&session, 5, None).await?;
    if peers.is_empty() {
        println!("no peers found — the other client must be running `yapayapa peers connect`");
        return Ok(());
    }
    let contacts = session.store.list_contacts()?;
    for p in peers {
        let known = contacts
            .iter()
            .find(|c| peer_id_for(&c.public_id) == p.peer_id);
        match known {
            Some(c) => println!("{}  {}  = @{}", p.peer_id, p.addr, c.username),
            None => println!("{}  {}  (not one of your contacts)", p.peer_id, p.addr),
        }
    }
    Ok(())
}

/// Rendezvous with a specific contact on the LAN: advertise + listen, browse
/// for them, and use whichever direction connects first. Then exchange
/// queued envelopes both ways.
pub async fn peers_connect(config: Config, peer: String) -> anyhow::Result<()> {
    let session = Session::load(config)?;
    // Resolve the target: username / public id of a *contact*, or raw peer id.
    let contact = session
        .store
        .contact_by_selector(&peer)?
        .or_else(|| {
            session
                .store
                .list_contacts()
                .ok()?
                .into_iter()
                .find(|c| peer_id_for(&c.public_id) == peer)
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "'{peer}' is not a local contact — LAN transport requires a pinned contact identity \
                 (add them with `yapayapa contacts add` while online first)"
            )
        })?;
    let expected_peer_id = peer_id_for(&contact.public_id);
    println!(
        "looking for @{} ({expected_peer_id}) on the local network…",
        contact.username
    );

    let listener = TcpListener::bind(("0.0.0.0", 0)).await?;
    let port = listener.local_addr()?.port();

    // Advertise while we search, so the peer can also find us.
    let daemon = ServiceDaemon::new()?;
    let my_peer_id = peer_id_for(&session.keystore.profile.public_id);
    let info = ServiceInfo::new(
        SERVICE_TYPE,
        &my_peer_id,
        &format!("{my_peer_id}.local."),
        "",
        port,
        None,
    )?
    .enable_addr_auto();
    daemon.register(info)?;

    let stream = tokio::select! {
        inbound = accept_from(&listener) => inbound?,
        outbound = dial_peer(&session, &expected_peer_id) => outbound?,
    };
    let _ = daemon.shutdown();

    let (mut stream, peer_identity) = handshake(&session, stream, Some(&contact)).await?;
    println!(
        "authenticated encrypted LAN connection with @{}",
        contact.username
    );
    exchange(&session, &mut stream, &contact, &peer_identity).await
}

async fn accept_from(listener: &TcpListener) -> anyhow::Result<TcpStream> {
    let (stream, _) = listener.accept().await?;
    Ok(stream)
}

async fn dial_peer(session: &Session, expected_peer_id: &str) -> anyhow::Result<TcpStream> {
    loop {
        let peers = browse(session, 3, None).await?;
        if let Some(p) = peers.iter().find(|p| p.peer_id == expected_peer_id) {
            match TcpStream::connect(p.addr).await {
                Ok(stream) => return Ok(stream),
                Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
            }
        }
    }
}

/// Mutual authentication: exchange Hello (identity + nonce), verify the
/// peer's identity equals the pinned contact identity, then exchange and
/// verify challenge signatures. Aborts on any mismatch.
async fn handshake(
    session: &Session,
    mut stream: TcpStream,
    expected: Option<&Contact>,
) -> anyhow::Result<(TcpStream, PublicIdentity)> {
    let my_nonce: [u8; 32] = rand::random();
    write_frame(
        &mut stream,
        &LanFrame::Hello {
            public_id: session.keystore.profile.public_id.clone(),
            identity: session.keystore.identity.public(),
            nonce: b64(&my_nonce),
        },
    )
    .await?;

    let LanFrame::Hello {
        public_id,
        identity,
        nonce,
    } = read_frame(&mut stream).await?
    else {
        anyhow::bail!("peer did not start with Hello");
    };
    identity
        .verify_prekey()
        .map_err(|_| anyhow::anyhow!("peer presented an inconsistent identity"))?;

    // The peer must be a pinned contact with exactly this identity.
    let contact = match expected {
        Some(c) => c.clone(),
        None => session
            .store
            .contact_by_selector(&public_id)?
            .ok_or_else(|| {
                anyhow::anyhow!("rejecting LAN connection from unknown peer {public_id}")
            })?,
    };
    if contact.public_id != public_id || contact.identity != identity {
        anyhow::bail!(
            "SECURITY: LAN peer claims to be @{} but presented a different identity key — refusing",
            contact.username
        );
    }

    // Prove we hold our signing key; require the same from the peer.
    let peer_nonce = b64_arr::<32>(&nonce).ok_or_else(|| anyhow::anyhow!("bad peer nonce"))?;
    let mut to_sign = Vec::new();
    to_sign.extend_from_slice(LAN_AUTH_DOMAIN);
    to_sign.extend_from_slice(&peer_nonce);
    to_sign.extend_from_slice(session.keystore.profile.public_id.as_bytes());
    let sig = session.keystore.identity.sign(&to_sign);
    write_frame(&mut stream, &LanFrame::Auth { sig: b64(&sig) }).await?;

    let LanFrame::Auth { sig } = read_frame(&mut stream).await? else {
        anyhow::bail!("peer skipped authentication");
    };
    let sig = b64_vec(&sig)
        .and_then(|v| <[u8; 64]>::try_from(v).ok())
        .ok_or_else(|| anyhow::anyhow!("malformed peer signature"))?;
    let mut expected_msg = Vec::new();
    expected_msg.extend_from_slice(LAN_AUTH_DOMAIN);
    expected_msg.extend_from_slice(&my_nonce);
    expected_msg.extend_from_slice(contact.public_id.as_bytes());
    contact
        .identity
        .verify(&expected_msg, &sig)
        .map_err(|_| anyhow::anyhow!("peer failed the identity challenge — refusing"))?;

    Ok((stream, identity))
}

/// Push queued envelopes addressed to this peer and receive theirs, acking
/// both ways. Ends when both sides said Bye.
async fn exchange(
    session: &Session,
    stream: &mut TcpStream,
    contact: &Contact,
    _peer_identity: &PublicIdentity,
) -> anyhow::Result<()> {
    let outgoing: Vec<_> = session
        .store
        .outbox_list()?
        .into_iter()
        .filter(|e| e.recipient_id == contact.user_id)
        .collect();
    println!("sending {} queued envelope(s) over LAN…", outgoing.len());
    for e in &outgoing {
        let envelope = serde_json::from_str(&e.envelope_json)?;
        write_frame(
            stream,
            &LanFrame::Msg {
                message: WireMessage {
                    message_id: e.message_id,
                    sender_id: session.keystore.profile.user_id,
                    recipient_id: e.recipient_id,
                    group_id: e.group_id,
                    sent_at: e.sent_at,
                    envelope,
                },
            },
        )
        .await?;
    }
    write_frame(stream, &LanFrame::Bye).await?;

    let mut sent_done = false;
    let mut received = 0usize;
    let mut acked = 0usize;
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(20), read_frame(stream)).await;
        let frame = match frame {
            Ok(Ok(f)) => f,
            _ => break,
        };
        match frame {
            LanFrame::Msg { message } => {
                if message.recipient_id != session.keystore.profile.user_id {
                    continue; // not for us; never relay
                }
                match handle_incoming(session, &message).await {
                    Ok(Incoming::Stored { line, .. }) => {
                        println!("{line} (via LAN)");
                        received += 1;
                        write_frame(
                            stream,
                            &LanFrame::Ack {
                                message_id: message.message_id,
                            },
                        )
                        .await?;
                    }
                    Ok(_) => {
                        write_frame(
                            stream,
                            &LanFrame::Ack {
                                message_id: message.message_id,
                            },
                        )
                        .await?;
                    }
                    Err(e) => println!("! rejected LAN message: {e}"),
                }
            }
            LanFrame::Ack { message_id } => {
                session.store.set_state(message_id, LocalState::Delivered)?;
                session.store.outbox_remove(message_id)?;
                acked += 1;
            }
            LanFrame::Bye => {
                if sent_done {
                    break;
                }
                sent_done = true;
                if acked >= outgoing.len() {
                    break;
                }
            }
            LanFrame::Hello { .. } | LanFrame::Auth { .. } => break,
        }
        if sent_done && acked >= outgoing.len() {
            break;
        }
    }
    println!(
        "LAN exchange complete: delivered {acked} of {} queued, received {received}",
        outgoing.len()
    );
    Ok(())
}

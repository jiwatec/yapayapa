# YapaYapa

Encrypted messaging that lives in your terminal. End-to-end encrypted,
works offline, built in Rust.

**Status: MVP under active development.**

## Security, honestly

Every message is encrypted on your device before it leaves (X25519, Ed25519,
ChaCha20-Poly1305, HKDF-SHA256, Argon2id, BLAKE3 — audited primitive crates).
The server only ever stores ciphertext, usernames, and public keys — never
private keys, never readable messages.

That said, the protocol composition is a **non-audited MVP**. It is not the
Signal protocol: no double ratchet, no forward secrecy. Don't use it for
high-risk communication. Migration to a mature Signal/MLS library is planned.

## Features

- End-to-end encrypted direct messages, live over WebSocket
- Works offline: encrypted local history and outbox, auto-retry on reconnect
- Server queues ciphertext for offline recipients — no duplicates, ever
- LAN mode: message peers directly over WiFi with no internet at all
- Group chats (up to 20, with roles and rotating keys)
- Encrypted image sharing (PNG/JPEG/WebP)
- Contact verification with identity fingerprints
- A clean full-screen terminal UI, plus plain CLI commands

## Quick start

You need a running backend (see below), then:

```bash
cargo build --release -p yapayapa
install -Dm755 target/release/yapayapa ~/.local/bin/yapayapa

yapayapa register     # pick a username + password
yapayapa add <friend> # add a contact
yapayapa              # open the app
```

Running `yapayapa` with no arguments opens the home screen:

- **Enter** — jump into your chat
- **ctrl+p** — pick from a command list
- **tab** — see every command explained
- **Esc** — quit

## Commands

Everyday:

```bash
yapayapa                          # home screen
yapayapa chat bob                 # full-screen encrypted chat
yapayapa add bob                  # add a contact (username or yp_ public ID)
yapayapa friends                  # list your contacts
yapayapa img bob ./photo.png      # send an encrypted image
yapayapa group "weekend crew"     # create a group chat
yapayapa sync                     # push queued offline messages now
```

Everything else:

```bash
yapayapa profile                  # your username, public ID, fingerprint
yapayapa verify bob               # compare fingerprints, mark verified
yapayapa find bob                 # look up a user without adding them
yapayapa status                   # connection, outbox, unread counts
yapayapa chat bob --plain         # line-based chat instead of the UI
yapayapa chat <group-id>          # groups open with plain `chat` too
yapayapa peers list               # discover LAN peers (opt-in, on demand)
yapayapa peers connect bob        # deliver directly over LAN, no internet
yapayapa attachments list         # received images
yapayapa open-image <message-id>  # decrypt and open with your viewer
```

Long forms (`contacts add`, `outbox retry`, `groups create`, …) still work.

## Running the backend

Point it at any PostgreSQL — migrations apply automatically on startup:

```bash
DATABASE_URL=postgres://user:pass@host:5432/db BIND_ADDR=127.0.0.1:8080 \
  cargo run --release -p yapayapa-backend
```

Or with no database (data lost on restart — for trying it out):

```bash
YAPAYAPA_MEM_STORE=1 BIND_ADDR=127.0.0.1:8080 cargo run --release -p yapayapa-backend
```

The client talks to `http://127.0.0.1:8080` by default; set `YAPAYAPA_SERVER`
to use a remote server. For the cloud, `render.yaml` deploys the backend to
Render (built natively with cargo) with hosted PostgreSQL such as Neon.

## Two accounts on one machine

Each account is just a data directory:

```bash
# Terminal 1 — alice
export YAPAYAPA_DATA_DIR=~/.local/share/yapayapa-alice
yapayapa register
yapayapa add bob
yapayapa chat bob

# Terminal 2 — bob
export YAPAYAPA_DATA_DIR=~/.local/share/yapayapa-bob
yapayapa register
yapayapa add alice
yapayapa chat alice
```

## Windows client

The client builds and is tested on Windows (the backend runs on Linux).
Grab `yapayapa.exe` from the `yapayapa-windows-x86_64` artifact of the latest
[CI run](../../actions), or build with the MSVC toolchain:

```powershell
cargo build --release -p yapayapa
setx YAPAYAPA_SERVER http://<server-ip>:8080   # then open a new terminal
.\target\release\yapayapa.exe register
```

Data lives in `%APPDATA%\yapayapa`. The keystore is password-encrypted; the
full-screen UI works best in Windows Terminal.

## How offline works

With no network you can still open the app, read your history, and compose.
Messages queue in an encrypted local outbox and send automatically when a
connection returns. The server holds ciphertext for offline recipients until
they come back. If both sides are offline and not on the same LAN, the
message waits in the sender's outbox.

LAN mode is opt-in: discovery runs only while a `peers` command is active,
peers verify each other's identity keys before exchanging anything, and the
envelopes are identical to the relay path — LAN never weakens encryption.
While active, mDNS reveals your presence to the local network as a
pseudonymous ID.

## Known limitations

- One device per account; losing your keystore means losing your identity
  and history — back up your data directory
- No forward secrecy or post-compromise security yet
- The server sees metadata: who talks to whom, when, and message sizes
- Backend targets Linux; the client also runs on Windows

## Stack

Rust workspace: `client/` (Clap, Ratatui, rusqlite), `backend/` (Axum, SQLx,
PostgreSQL), `common/` (shared crypto + wire types). CI runs fmt, clippy,
tests against real PostgreSQL, cargo-audit, and a Windows client build.

## License

MIT — see [LICENSE](LICENSE).

# YapaYapa

YapaYapa is a terminal-based, end-to-end encrypted chat app built in Rust. Your
messages are encrypted on your device, work offline, and can even be sent
directly over your local network — nothing readable ever touches the server.
It's a non-audited hobby project: fun to use and learn from, not meant for
high-risk communication.

The project consists of:

- **yapayapa (client)**: a terminal chat client (full-screen TUI + plain CLI
  commands) that handles the encryption, local history, and an offline outbox.
- **yapayapa-backend (server)**: a relay (Axum + PostgreSQL) that only ever
  stores and forwards ciphertext — never your keys or readable messages.
- **common**: shared crypto and message types used by both sides, so the client
  and server can't drift apart.

## Prerequisites

Nothing if you use the one-line installer — it downloads a prebuilt binary. Only
if you build from source do you need the **Rust** toolchain (https://rustup.rs).

## Installation

### Option 1: One-line install (recommended)

Linux / macOS, no Rust needed:

```bash
curl -fsSL https://raw.githubusercontent.com/jiwatec/yapayapa/main/install.sh | bash
```

Windows: download `yapayapa-windows-x86_64.exe` from the
[latest release](https://github.com/jiwatec/yapayapa/releases/latest).

### Option 2: Build from source

```bash
git clone https://github.com/jiwatec/yapayapa.git
cd yapayapa
cargo build --release -p yapayapa
install -Dm755 target/release/yapayapa ~/.local/bin/yapayapa
```

## Usage

1. Create your account:

   ```bash
   yapayapa register
   ```

2. Add a friend by username (and have them add you back):

   ```bash
   yapayapa add <friend>
   ```

3. Open the chat and start typing:

   ```bash
   yapayapa chat <friend>
   ```

Messages are delivered live, or queued and delivered later if the other person
is offline.

## Commands

Everyday:

```bash
yapayapa                          # home screen
yapayapa chat bob                 # full-screen encrypted chat
yapayapa add bob                  # add a contact (username or yp_ public ID)
yapayapa friends                  # list your contacts
yapayapa img bob ./photo.png      # send an encrypted image (work in progress)
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
yapayapa attachments list         # received images (work in progress)
yapayapa open-image <message-id>  # open a received image (work in progress)
```

Long forms (`contacts add`, `outbox retry`, `groups create`, …) still work.

Inside an open chat you can also type:

```bash
/img <path>    # send an encrypted image (work in progress)
/clear         # clear this chat's local history (type /clear twice to confirm)
```

## How offline works

With no network you can still open the app, read your history, and compose.
Messages queue in an encrypted local outbox and send automatically when a
connection returns. The server holds ciphertext for offline recipients until
they come back. If both sides are offline and not on the same LAN, the message
waits in the sender's outbox.

LAN mode is opt-in: discovery runs only while a `peers` command is active, peers
verify each other's identity keys before exchanging anything, and the envelopes
are identical to the relay path — LAN never weakens encryption. While active,
mDNS reveals your presence to the local network as a pseudonymous ID.

## Known limitations

- One device per account; losing your keystore means losing your identity and
  history — back up your data directory.
- No forward secrecy or post-compromise security yet.
- The server sees metadata: who talks to whom, when, and message sizes.
- Backend targets Linux. The client is tested on Linux; the macOS and Windows
  builds are provided but not yet verified end-to-end.

## Self-hosting the backend (optional)

By default the client uses the hosted server, so you don't need one. To run your
own, point it at any PostgreSQL (migrations apply automatically on startup):

```bash
DATABASE_URL=postgres://user:pass@host:5432/db BIND_ADDR=127.0.0.1:8080 \
  cargo run --release -p yapayapa-backend
```

Then point the client at it with `YAPAYAPA_SERVER=http://127.0.0.1:8080`.

## Directory Structure

```
yapayapa/
├── client/      # Terminal chat client (the `yapayapa` binary)
├── backend/     # Relay server (the `yapayapa-backend` binary)
├── common/      # Shared crypto + message types
├── migrations/  # SQL schema, applied automatically on startup
└── render.yaml  # Deploy config for Render
```

## License

MIT — see [LICENSE](LICENSE).

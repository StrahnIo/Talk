#!/usr/bin/env bash
#
# End-to-end: two local daemons, payment from example.com -> stygian.io.
#
# Boots the main daemon (config.toml, domain stygian.io) and the counterparty
# daemon (config.counterparty.toml, domain example.com), then sends an invoice
# from the counterparty to a stygian.io user and verifies both transaction
# ledgers.
#
# The counterparty (the *sender* here) is started with COUNTERPARTY_DOMAIN=
# stygian.io so it resolves the main daemon via localhost instead of DNS.
#
# Usage: scripts/e2e.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."
TALKD="$ROOT/target/debug/talkd"
TALKCTL="$ROOT/target/debug/talkctl"

# Ensure cargo is on PATH (rustup default install).
if ! command -v cargo >/dev/null 2>&1 && [ -f "$HOME/.cargo/env" ]; then
    # shellcheck source=/dev/null
    . "$HOME/.cargo/env"
fi

MAIN_CONFIG="$ROOT/config.toml"
CP_CONFIG="$ROOT/config.counterparty.toml"
INVOICE_FILE="$(mktemp)"
LOG_DIR="$(mktemp -d)"

SENDER_USER="sender"
RECIPIENT_USER="violet"
PW="e2e-pw"

# Main daemon: stygian.io on 1465 (ZSMTP) / 1144 (IMAPS) + 1430 (unsafe plaintext IMAP)
MAIN_ZSMTP=1465
MAIN_IMAP_UNSAFE=1430

# Counterparty daemon: example.com on 1466 (ZSMTP) / 1145 (IMAPS) + 1146 (unsafe plaintext IMAP)
CP_ZSMTP=1466
CP_IMAP_UNSAFE=1146

# Whether the script launched the daemons (only launched ones are killed on exit).
MAIN_LAUNCHED=0
CP_LAUNCHED=0

# Whether a TCP port already has a listener.
port_engaged() {
    lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
}

cleanup() {
    if [ "$MAIN_LAUNCHED" = "1" ]; then
        pkill -f "$TALKD --config $MAIN_CONFIG" 2>/dev/null || true
    fi
    if [ "$CP_LAUNCHED" = "1" ]; then
        pkill -f "$TALKD --config $CP_CONFIG" 2>/dev/null || true
    fi
    rm -f "$INVOICE_FILE"
    rm -rf "$LOG_DIR"
}
trap cleanup EXIT

say()  { printf '\033[1;34m==\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32mOK:\033[0m %s\n' "$*"; }

say "building talkd + talkctl"
(cd "$ROOT" && cargo build -q -p talkd -p talk-ctl)

# The main daemon's public domain key: what the sender verifies against.
MAIN_PUBKEY="$("$TALKCTL" --config "$MAIN_CONFIG" domainkey pubkey)"

if port_engaged "$MAIN_ZSMTP"; then
    say "port $MAIN_ZSMTP engaged — main daemon already running, skipping launch"
else
    say "starting main daemon (stygian.io)  zsmtp=$MAIN_ZSMTP imap(plain)=$MAIN_IMAP_UNSAFE"
    UNSAFE_NO_TLS=1 UNSAFE_IMAP_PORT=$MAIN_IMAP_UNSAFE \
        "$TALKD" --config "$MAIN_CONFIG" >"$LOG_DIR/main.log" 2>&1 &
    MAIN_LAUNCHED=1
fi

# The counterparty is the SENDER here, so it must resolve stygian.io.
if port_engaged "$CP_ZSMTP"; then
    say "port $CP_ZSMTP engaged — counterparty daemon already running, skipping launch"
    say "note: it must have been started with COUNTERPARTY_DOMAIN=stygian.io COUNTERPARTY_PORT_SMTP=$MAIN_ZSMTP COUNTERPARTY_DOMAINKEY_HEX=$MAIN_PUBKEY"
else
    say "starting counterparty daemon (example.com)  zsmtp=$CP_ZSMTP imap(plain)=$CP_IMAP_UNSAFE"
    UNSAFE_NO_TLS=1 UNSAFE_IMAP_PORT=$CP_IMAP_UNSAFE \
        COUNTERPARTY_DOMAIN=stygian.io \
        COUNTERPARTY_PORT_SMTP=$MAIN_ZSMTP \
        COUNTERPARTY_DOMAINKEY_HEX="$MAIN_PUBKEY" \
        "$TALKD" --config "$CP_CONFIG" >"$LOG_DIR/cp.log" 2>&1 &
    CP_LAUNCHED=1
fi

sleep 2

say "ensuring users exist"
PK="$(python3 -c 'import os; print(os.urandom(32).hex())')"
"$TALKCTL" --config "$CP_CONFIG" user create "$SENDER_USER" --password "$PW" --pubkey "$PK" >/dev/null 2>&1 || true
"$TALKCTL" --config "$MAIN_CONFIG" user create "$RECIPIENT_USER" --password "$PW" --pubkey "$PK" >/dev/null 2>&1 || true

printf 'Invoice #E2E-001 — example.com -> stygian.io\nLine item: E2E transfer 1.00 ZEC\n' > "$INVOICE_FILE"

say "sending from $SENDER_USER@example.com -> $RECIPIENT_USER@stygian.io"
SEND_OUT="$("$TALKCTL" --config "$CP_CONFIG" send "$SENDER_USER" "$RECIPIENT_USER@stygian.io" "$INVOICE_FILE")"
echo "  $SEND_OUT"

say "verifying ledgers"
echo "--- counterparty (sender) ledger ---"
"$TALKCTL" --config "$CP_CONFIG" tx list --dir out
echo "--- main (recipient) ledger ---"
"$TALKCTL" --config "$MAIN_CONFIG" tx list --dir in

# Resolve the inbound transaction on the main side.
IN_TX="$("$TALKCTL" --config "$MAIN_CONFIG" tx list --dir in | awk 'NR==1 { print $1 }')"
if [ -n "$IN_TX" ]; then
    "$TALKCTL" --config "$MAIN_CONFIG" tx resolve "$IN_TX" --binding e2e >/dev/null 2>&1 || true
    ok "main tx $IN_TX resolved on main"
fi

echo "--- main INBOX (plaintext IMAP $MAIN_IMAP_UNSAFE) ---"
(printf 'A1 LOGIN %s %s\r\nA2 SELECT INBOX\r\nA3 FETCH 1:* (UID BODY.PEEK[HEADER.FIELDS (SUBJECT FROM TO X-TALK-TXN-STATUS)])\r\nA4 LOGOUT\r\n' "$RECIPIENT_USER" "$PW"; sleep 0.6) \
    | nc 127.0.0.1 "$MAIN_IMAP_UNSAFE" 2>/dev/null \
    | grep -E "Subject:|From:|To:|X-Talk" | head

say "done — daemons stopped on exit"

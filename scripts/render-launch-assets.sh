#!/usr/bin/env bash
set -euo pipefail

export TZ=UTC
export LC_ALL=C.UTF-8
export LANG=C.UTF-8
umask 077

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ASSET_PARENT="$ROOT_DIR/docs/assets"
ASSET_DIR="$ASSET_PARENT/launch"
mkdir -p "$ASSET_PARENT"

DEMO_DIR=""
CHROMIUM_DIR=""
STAGING_DIR=""
SERVER_PID=""
PORT=""

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  for directory in "$DEMO_DIR" "$CHROMIUM_DIR" "$STAGING_DIR"; do
    if [[ -n "$directory" ]]; then
      rm -rf -- "$directory"
    fi
  done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command in uv curl chromium convert identify timeout python3; do
  command -v "$command" >/dev/null || {
    printf 'Missing required command: %s\n' "$command" >&2
    exit 1
  }
done
FONT_LIST=$(convert -list font)
for font in 'Font: DejaVu-Sans' 'Font: DejaVu-Sans-Bold'; do
  if [[ "$FONT_LIST" != *"$font"* ]]; then
    printf 'Missing required ImageMagick font: %s\n' "$font" >&2
    exit 1
  fi
done

DEMO_DIR=$(mktemp -d /tmp/glassbox-launch-assets.XXXXXX)
CHROMIUM_DIR=$(mktemp -d "$HOME/glassbox-launch-assets.XXXXXX")
STAGING_DIR=$(mktemp -d "$ASSET_PARENT/.launch-stage.XXXXXX")
NONCE=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
PORT_FILE="$DEMO_DIR/port"

cd "$ROOT_DIR"
uv run --locked python3 scripts/render-launch-server.py \
  --workspace "$DEMO_DIR/workspace" \
  --data-dir "$DEMO_DIR/data" \
  --nonce "$NONCE" \
  --port-file "$PORT_FILE" >"$DEMO_DIR/server.log" 2>&1 &
SERVER_PID=$!

server_failed() {
  printf 'Launch asset server exited before completing the render. Log: %s\n' \
    "$DEMO_DIR/server.log" >&2
  return 1
}

assert_server() {
  kill -0 "$SERVER_PID" 2>/dev/null || server_failed
  local response
  response=$(curl --noproxy '*' --fail --silent --show-error --max-time 2 \
    "http://127.0.0.1:$PORT/__glassbox_launch_ready__/$NONCE")
  if [[ "$response" != "$NONCE" ]]; then
    printf 'Launch server identity check failed.\n' >&2
    return 1
  fi
}

for ((attempt = 1; attempt <= 100; attempt++)); do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    server_failed
  fi
  if [[ -s "$PORT_FILE" ]]; then
    PORT=$(<"$PORT_FILE")
    if [[ "$PORT" =~ ^[0-9]+$ ]] && assert_server 2>/dev/null; then
      break
    fi
  fi
  sleep 0.1
done
if [[ -z "$PORT" ]]; then
  printf 'Launch asset server did not publish a port.\n' >&2
  exit 1
fi
assert_server

capture_dashboard() {
  local output=$1
  rm -f -- "$output"
  assert_server
  timeout 30 chromium --headless --disable-gpu --hide-scrollbars \
    --disable-background-networking --disable-sync --metrics-recording-only \
    --no-first-run --lang=en-US --window-size=1280,1331 \
    --screenshot="$output" "http://127.0.0.1:$PORT" >/dev/null 2>&1
  if [[ ! -s "$output" ]]; then
    printf 'Chromium did not create a fresh screenshot: %s\n' "$output" >&2
    exit 1
  fi
  assert_server
}

capture_dashboard "$CHROMIUM_DIR/dashboard.png"
convert "$CHROMIUM_DIR/dashboard.png" \
  -fill '#8f95ff' -draw 'roundrectangle 930,70 1236,110 12,12' \
  -fill '#080a0b' -font DejaVu-Sans-Bold -pointsize 16 \
  -annotate +953+98 'SYNTHETIC DEMO DATA' -depth 8 -strip \
  +set date:create +set date:modify \
  "$STAGING_DIR/dashboard.png"

assert_server
ROLLBACK_RESPONSE=$(curl --noproxy '*' --fail --silent --show-error --max-time 10 \
  -X POST "http://127.0.0.1:$PORT/__glassbox_launch_rollback__/$NONCE/3" \
  -H 'Content-Type: application/json' \
  -d '{"confirm":true}')
assert_server
VERIFY_RESPONSE=$(curl --noproxy '*' --fail --silent --show-error --max-time 2 \
  "http://127.0.0.1:$PORT/api/verify")
EVENTS_RESPONSE=$(curl --noproxy '*' --fail --silent --show-error --max-time 2 \
  "http://127.0.0.1:$PORT/api/events")
python3 - "$ROLLBACK_RESPONSE" "$VERIFY_RESPONSE" "$EVENTS_RESPONSE" \
  "$DEMO_DIR/workspace/launch-plan.md" <<'PY'
import json
from pathlib import Path
import sys

rollback = json.loads(sys.argv[1])
verification = json.loads(sys.argv[2])
events = json.loads(sys.argv[3])["events"]
target = Path(sys.argv[4])
assert rollback["status"] == "rolled_back"
assert rollback["rollback_receipt_id"] == 5
assert verification == {"valid": True, "event_count": 5, "broken_at": None}
assert len(events) == 5
assert events[0]["id"] == 5
assert events[0]["action"] == "file.rollback"
assert events[0]["metadata"]["rolled_back_event_id"] == 3
assert target.is_file()
assert target.read_text(encoding="utf-8") == ""
PY

capture_dashboard "$CHROMIUM_DIR/after-rollback.png"

convert "$STAGING_DIR/dashboard.png" \
  -gravity south -background '#111318' -splice 0x84 \
  -fill '#f5f7ff' -font DejaVu-Sans -pointsize 30 \
  -annotate +0+23 '1. Each submitted action gets a plain-language receipt' \
  "$STAGING_DIR/.frame-before.png"
convert "$CHROMIUM_DIR/after-rollback.png" \
  -fill '#8f95ff' -draw 'roundrectangle 930,70 1236,110 12,12' \
  -fill '#080a0b' -font DejaVu-Sans-Bold -pointsize 16 \
  -annotate +953+98 'SYNTHETIC DEMO DATA' \
  -gravity south -background '#111318' -splice 0x84 \
  -fill '#f5f7ff' -font DejaVu-Sans -pointsize 27 \
  -annotate +0+25 '2. A rollback receipt is added; the renderer verified the restored bytes' \
  "$STAGING_DIR/.frame-after.png"
convert \
  -delay 240 "$STAGING_DIR/.frame-before.png" \
  -delay 320 "$STAGING_DIR/.frame-after.png" \
  -loop 0 -layers Optimize -strip +set date:create +set date:modify \
  "$STAGING_DIR/walkthrough.gif"

convert "$STAGING_DIR/dashboard.png" \
  -resize '700x' -crop '610x570+85+35' +repage \
  -bordercolor '#252933' -border 1 "$STAGING_DIR/.social-preview.png"
convert -size 1280x640 xc:'#080a0b' \
  -fill '#8f95ff' -font DejaVu-Sans-Bold -pointsize 22 \
  -annotate +64+86 'LINUX ALPHA · SYNTHETIC DEMO' \
  -fill '#f5f7ff' -pointsize 66 -annotate +64+174 'Glassbox' \
  -font DejaVu-Sans -pointsize 38 \
  -annotate +64+252 'Receipts and guarded' \
  -annotate +64+302 'rollback for AI agents' \
  -fill '#a7adbd' -pointsize 23 \
  -annotate +64+390 'Plain-language receipts' \
  -annotate +64+426 'Tamper-evident chaining' \
  -annotate +64+462 'Live conflict checks before rollback' \
  -fill '#f5f7ff' -pointsize 20 \
  -annotate +64+560 'github.com/jckm14/glassbox' \
  "$STAGING_DIR/.social-preview.png" -geometry +646+34 -composite \
  -strip +set date:create +set date:modify \
  "$STAGING_DIR/social-card.png"

rm -f -- \
  "$STAGING_DIR/.frame-before.png" \
  "$STAGING_DIR/.frame-after.png" \
  "$STAGING_DIR/.social-preview.png"

# validate staged launch assets before publishing the directory as one set
python3 - "$STAGING_DIR" "$NONCE" <<'PY'
from pathlib import Path
import subprocess
import sys

stage = Path(sys.argv[1])
nonce = sys.argv[2].encode("ascii")
expected = {"dashboard.png", "walkthrough.gif", "social-card.png"}
actual = {path.name for path in stage.iterdir()}
assert actual == expected, (actual, expected)

def dimensions(path: Path) -> list[str]:
    output = subprocess.check_output(
        ["identify", "-format", "%w x %h\n", str(path)], text=True
    )
    return output.splitlines()

assert dimensions(stage / "dashboard.png") == ["1280 x 1331"]
assert dimensions(stage / "social-card.png") == ["1280 x 640"]
assert len(dimensions(stage / "walkthrough.gif")) == 2
for path in stage.iterdir():
    payload = path.read_bytes()
    assert nonce not in payload
    assert b"/home/" not in payload
    assert b"/tmp/" not in payload
PY
chmod 0755 "$STAGING_DIR"
chmod 0644 "$STAGING_DIR/dashboard.png" \
  "$STAGING_DIR/walkthrough.gif" \
  "$STAGING_DIR/social-card.png"

if [[ "${GLASSBOX_RENDER_TEST_FAIL_BEFORE_PUBLISH:-0}" == "1" ]]; then
  printf 'Injected failure before atomic asset publication.\n' >&2
  exit 97
fi

python3 - "$STAGING_DIR" "$ASSET_DIR" <<'PY'
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import sys

source = Path(sys.argv[1]).resolve()
destination = Path(sys.argv[2]).resolve()
if not destination.exists():
    os.rename(source, destination)
else:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = libc.renameat2
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    at_fdcwd = -100
    rename_exchange = 2  # RENAME_EXCHANGE
    result = renameat2(
        at_fdcwd,
        os.fsencode(source),
        at_fdcwd,
        os.fsencode(destination),
        rename_exchange,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), f"{source} <-> {destination}")
PY
rm -rf -- "$STAGING_DIR"
STAGING_DIR=""

printf 'Wrote %s, %s, and %s\n' \
  "$ASSET_DIR/dashboard.png" \
  "$ASSET_DIR/walkthrough.gif" \
  "$ASSET_DIR/social-card.png"

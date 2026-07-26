#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ASSET_DIR="$ROOT_DIR/docs/assets/launch"
DEMO_DIR=$(mktemp -d /tmp/glassbox-launch-assets.XXXXXX)
CHROMIUM_DIR=$(mktemp -d "$HOME/glassbox-launch-assets.XXXXXX")
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf -- "$DEMO_DIR" "$CHROMIUM_DIR"
}
trap cleanup EXIT

for command in uv curl chromium convert timeout python3; do
  command -v "$command" >/dev/null || {
    printf 'Missing required command: %s\n' "$command" >&2
    exit 1
  }
done

mkdir -p "$ASSET_DIR"
PORT=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)

cd "$ROOT_DIR"
uv run glassbox demo \
  --workspace "$DEMO_DIR/workspace" \
  --data-dir "$DEMO_DIR/data" >/dev/null
uv run glassbox serve \
  --host 127.0.0.1 \
  --port "$PORT" \
  --workspace "$DEMO_DIR/workspace" \
  --data-dir "$DEMO_DIR/data" >"$DEMO_DIR/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 50); do
  if curl --fail --silent --max-time 1 "http://127.0.0.1:$PORT/api/verify" >/dev/null; then
    break
  fi
  sleep 0.1
done
curl --fail --silent --max-time 2 "http://127.0.0.1:$PORT/api/verify" >/dev/null

timeout 30 chromium --headless --disable-gpu --hide-scrollbars \
  --window-size=1280,1331 \
  --screenshot="$CHROMIUM_DIR/dashboard.png" \
  "http://127.0.0.1:$PORT" >/dev/null 2>&1
convert "$CHROMIUM_DIR/dashboard.png" \
  -fill '#8f95ff' -draw 'roundrectangle 930,70 1236,110 12,12' \
  -fill '#080a0b' -font DejaVu-Sans-Bold -pointsize 16 \
  -annotate +953+98 'SYNTHETIC DEMO DATA' -depth 8 \
  "$ASSET_DIR/dashboard.png"

ROLLBACK_RESPONSE=$(curl --fail --silent --show-error --max-time 10 \
  -X POST "http://127.0.0.1:$PORT/api/events/3/rollback" \
  -H 'Content-Type: application/json' \
  -d '{"confirm":true}')
VERIFY_RESPONSE=$(curl --fail --silent --show-error --max-time 2 \
  "http://127.0.0.1:$PORT/api/verify")
python3 - "$ROLLBACK_RESPONSE" "$VERIFY_RESPONSE" "$DEMO_DIR/workspace/launch-plan.md" <<'PY'
import json
from pathlib import Path
import sys

rollback = json.loads(sys.argv[1])
verification = json.loads(sys.argv[2])
target = Path(sys.argv[3])
assert rollback["status"] == "rolled_back"
assert rollback["rollback_receipt_id"] == 5
assert verification == {"valid": True, "event_count": 5, "broken_at": None}
assert target.is_file()
assert target.read_text(encoding="utf-8") == ""
PY

timeout 30 chromium --headless --disable-gpu --hide-scrollbars \
  --window-size=1280,1331 \
  --screenshot="$CHROMIUM_DIR/after-rollback.png" \
  "http://127.0.0.1:$PORT" >/dev/null 2>&1

convert "$ASSET_DIR/dashboard.png" \
  -gravity south -background '#111318' -splice 0x84 \
  -fill '#f5f7ff' -font DejaVu-Sans -pointsize 30 \
  -annotate +0+23 '1. Each submitted action gets a plain-language receipt' \
  "$ASSET_DIR/.frame-before.png"
convert "$CHROMIUM_DIR/after-rollback.png" \
  -fill '#8f95ff' -draw 'roundrectangle 930,70 1236,110 12,12' \
  -fill '#080a0b' -font DejaVu-Sans-Bold -pointsize 16 \
  -annotate +953+98 'SYNTHETIC DEMO DATA' \
  -gravity south -background '#111318' -splice 0x84 \
  -fill '#f5f7ff' -font DejaVu-Sans -pointsize 30 \
  -annotate +0+23 '2. Guarded rollback restores the file and adds a new receipt' \
  "$ASSET_DIR/.frame-after.png"
convert \
  -delay 240 "$ASSET_DIR/.frame-before.png" \
  -delay 320 "$ASSET_DIR/.frame-after.png" \
  -loop 0 -layers Optimize "$ASSET_DIR/walkthrough.gif"

convert "$ASSET_DIR/dashboard.png" \
  -resize '700x' -crop '610x570+85+35' +repage \
  -bordercolor '#252933' -border 1 "$ASSET_DIR/.social-preview.png"
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
  "$ASSET_DIR/.social-preview.png" -geometry +646+34 -composite \
  "$ASSET_DIR/social-card.png"

rm -f -- \
  "$ASSET_DIR/.frame-before.png" \
  "$ASSET_DIR/.frame-after.png" \
  "$ASSET_DIR/.social-preview.png"

printf 'Wrote %s, %s, and %s\n' \
  "$ASSET_DIR/dashboard.png" \
  "$ASSET_DIR/walkthrough.gif" \
  "$ASSET_DIR/social-card.png"

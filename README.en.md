# BruteForceWF

**English** | [Tiếng Việt](README.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![hashcat](https://img.shields.io/badge/hashcat-%E2%89%A56.2-red.svg)](https://hashcat.net/hashcat/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#contributing)

**BruteForceWF** is a WiFi security audit toolkit for your own network: scan nearby access points, capture the PMKID or EAPOL handshake, and crack offline with hashcat on a GPU. It ships with Vietnamese wordlists tuned for password habits in Vietnam.

> [!WARNING]
> **Use only on networks you own or have written authorization for.** Accessing someone else's WiFi is a criminal offence (in Vietnam: Article 289 of the Penal Code). The sole purpose of this tool is to check whether your own home network password is strong enough.

## Table of contents

- [Features](#features)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Wordlists](#wordlists)
- [Performance](#performance)
- [Project structure](#project-structure)
- [Technical notes](#technical-notes)
- [Contributing](#contributing)
- [References](#references)
- [License](#license)

## Features

- **End-to-end in one command** — `audit.py` scans APs, lets you pick a target, captures and cracks automatically.
- **Dual capture** — PMKID and EAPOL in a single `hcxdumptool` session, with automatic fallback to an `airodump-ng` handshake when no valid hash is obtained.
- **Automatic conversion** — PCAP/PCAPNG to hashcat mode `22000` via `hcxpcapngtool`.
- **Multi-stage hashcat orchestration** — dictionary, rules, numeric masks and hybrid attacks, stopping as soon as the password is recovered.
- **Vietnamese wordlists** — 405k real WiFi passwords, birthdays, given names and common passwords.
- **Personalized wordlists** — `gen_wordlist.py` generates mutations from your own names, phone numbers and birthdays.
- **Friendly terminal UI** — AP scan table, attack plan and result panel when [`rich`](https://github.com/Textualize/rich) is installed (optional; falls back to plain text automatically).
- **Cross-platform** — capture on any Linux distribution; crack on Windows or Linux.

## How it works

WPA2 **cannot** be brute-forced "online": every attempt requires a fresh 4-way handshake. The only viable approach is offline cracking:

```
Scan APs  →  Capture  →  Convert  →  Crack
Linux        PMKID/EAPOL  .hc22000    hashcat (GPU)
             handshake    (22000)
```

1. **Capture** the PMKID or EAPOL handshake of the target network (Linux + a WiFi card supporting monitor mode).
2. **Convert** it to hash format `22000`.
3. **Crack offline** with hashcat on a GPU — hundreds of thousands of attempts per second.

## Requirements

| Component | Requirement |
|---|---|
| Crack (Windows) | hashcat ≥ 6.2 + NVIDIA driver. Reference machine: GTX 1650 4GB ≈ **150–250 kH/s** |
| Convert | hcxtools (`hcxpcapngtool`) — win64 build available, or convert on Linux |
| Capture | Any Linux distribution (Ubuntu/Debian/Kali/Arch...) + a WiFi card supporting **monitor mode + packet injection**. External cards: Alfa AWUS036ACM/ACH; most laptop cards work under Linux. |
| Linux tools | `hcxdumptool` ≥ 6.3, `hcxtools`, `aircrack-ng` |

Installation:

```bash
# Ubuntu / Debian
sudo apt install aircrack-ng hcxdumptool hcxtools

# Arch Linux
sudo pacman -S aircrack-ng hcxdumptool hcxtools iw
```

Optional — a richer terminal UI with `rich` (colored tables, result panel, stage separators). Not required: without `rich`, everything falls back to plain text.

```bash
sudo pacman -S python-rich        # Arch
sudo apt install python3-rich     # Ubuntu / Debian
# or: python3 -m pip install rich
```

> `audit.py` runs under `sudo`, so install `rich` for the system environment (as shown above) rather than with `pip --user`.

> Kali is not required — a Kali/live USB is only convenient because the tools and drivers come preinstalled. Intel cards (AX200/AX210) can do monitor mode but injection is poor: passive handshake capture works, while deauth/PMKID attacks are better served by MediaTek/Ralink/Atheros cards (e.g. Alfa).

> WSL2 + usbipd usually **cannot** do monitor mode (the WSL kernel lacks cfg80211/mac80211 drivers) — use a live USB or dual-boot Linux instead.

## Quick start

```bash
sudo python3 audit.py
```

`audit.py` runs the whole workflow: it scans nearby APs (SSID, BSSID, channel, band, signal, security), lets you choose a target by index, captures PMKID + EAPOL with `hcxdumptool`, falls back to a handshake when no usable hash was produced, filters hashes down to the target BSSID, and then invokes `crack.py`. Your WiFi is temporarily interrupted during capture and restored afterwards (NetworkManager).

Main options:

```bash
sudo python3 audit.py --iface wlo1          # select the interface
sudo python3 audit.py --pmkid-minutes 5     # PMKID capture duration
sudo python3 audit.py --hs-seconds 60       # handshake fallback duration
sudo python3 audit.py --mask-lens 8,9 --phone --deep
sudo python3 audit.py --wordlist custom.txt
sudo python3 audit.py --yes                 # skip the ownership confirmation
```

Before capturing, the script verifies that `hashcat -I` reports an OpenCL/CUDA backend and validates arguments and wordlists (relative paths are resolved against the current directory).

## Usage

### 1. Capture (Linux)

Note the BSSID and channel of the target AP (from `iw dev`, the router admin page, or an `airodump-ng` scan).

#### PMKID + EAPOL with hcxdumptool (clientless, try first)

```bash
sudo ./capture/pmkid.sh wlan0 5        # scan for 5 minutes, all channels
sudo ./capture/pmkid.sh wlan0 5 6      # or pin a channel
sudo ./capture/pmkid.sh wlan0 5 6c     # 6GHz: channel + band suffix (a=2.4, b=5, c=6)
sudo ./capture/pmkid.sh wlan0 5 6 AA:BB:CC:DD:EE:FF   # target AP only (recommended)
```

- A single `hcxdumptool` session both requests **PMKID** and captures **EAPOL** (active deauth/association); the script stops early once a PMKID or a complete M1M2/M1M2M3 pair is captured.
- No connected client is required. PMKID only works against APs still vulnerable to the PMKID attack; EAPOL needs a client reconnect (hcxdumptool deauths automatically).
- Output: `captures/pmkid-*.pcapng` + `.hc22000` (auto-converted when `hcxpcapngtool` is available); files are mode `600`, the `captures/` directory is mode `700`.
- Pass a BSSID to capture only the target AP (BPF `wlan addr3`), avoiding hashes from neighbouring APs.
- The script adapts to the installed hcxdumptool version: from **6.3** it uses `-w`/`--rds` and `-c` with a band suffix (`40` → `40b`, 6GHz uses `c`); older versions use `-o`/`--enable_status`.

#### Handshake fallback with airodump-ng

```bash
sudo ./capture/handshake.sh wlan0 AA:BB:CC:DD:EE:FF 6
# include a client MAC to deauth the right target:
sudo ./capture/handshake.sh wlan0 AA:BB:CC:DD:EE:FF 6 11:22:33:44:55:66 60
# 6GHz: append the band (2.4 / 5 / 6):
sudo ./capture/handshake.sh wlan0 AA:BB:CC:DD:EE:FF 5 "" 60 6
```

- The script runs `airodump-ng` with short deauth bursts to force clients to reconnect (your network only) and stops once `hcxpcapngtool` produces a hash. If the capture is missing frames (aircrack-ng false positive), it keeps waiting and retries within the remaining time.
- Devices with PMF/802.11w enabled may ignore deauth — in that case simply wait for the client to reconnect on its own.
- Output: `captures/hs-*.hc22000`.

After capture, copy the `.hc22000` file to the Windows machine (`scp` or USB).

### 2. Convert (if you don't have a .hc22000)

```bash
hcxpcapngtool -o capture.hc22000 capture.pcapng
```

Run it on Linux, or use `hcxpcapngtool.exe` (hcxtools win64) on Windows. `crack.py` converts automatically when you pass a pcap file and the tool is available in PATH.

### 3. Crack (Windows / Linux)

Install hashcat: download from <https://hashcat.net/hashcat/>, extract (e.g. `C:\hashcat`), add it to PATH or pass `--hashcat`. On Arch: `sudo pacman -S hashcat opencl-nvidia` plus an NVIDIA driver (`nvidia-open` for GTX 1650 and newer, or `nvidia`); verify with `hashcat -I`.

```powershell
python crack.py captures\hs-20261114-203000.hc22000
```

Default attack chain (stops as soon as the password is recovered):

1. **Dictionary** — `personal.txt` (if present) → `vn-wifi.txt` (~405k) → `vn-common.txt` (~3.4k) → `dates.txt` → `vn-names.txt` → `rockyou.txt`/`top-1m.txt` (if present).
2. **best64 rules** — mutations of the smaller wordlists; rockyou/top-1M only run with `--deep`.
3. **Numeric masks** — 8 digits by default; `--mask-lens 8,9` adds length 9; `--phone` adds a Vietnamese phone-number mask (10 digits).
4. **Hybrid** — `--deep` only: `vn-base.txt`/`personal.txt` combined with 3–4 trailing digits (e.g. `matkhau123`).

Other options:

```powershell
python crack.py capture.hc22000 --dry-run          # show the plan, run nothing
python crack.py capture.hc22000 --show-only        # print passwords already cracked in the potfile
python crack.py capture.hc22000 --phone            # add Vietnamese phone-number masks
python crack.py capture.hc22000 --deep             # add rockyou+best64, hybrid (slow)
python crack.py capture.hc22000 --wordlist C:\lists\custom.txt --mask-lens 8,9
```

## Wordlists

| File | Contents |
|---|---|
| `vn-wifi.txt` | **405k real Vietnamese WiFi passwords** (from the WiFi Chùa app, public data), filtered to 8–63 characters and deduplicated |
| `vn-common.txt` | ~3.4k hand-curated common passwords in Vietnam (ISP, router, words + numeric suffixes), **≥ 8 characters** |
| `dates.txt` | 20.8k birthdays as `DDMMYYYY` (1970–2026) |
| `vn-names.txt` | 2k Vietnamese name combinations ≥ 8 characters |
| `vn-base.txt` | short base words, used for rules/hybrid |
| `personal.txt` | generated by `gen_wordlist.py` from your own information — the most effective list; used automatically when present |

The first three lists are bundled with the repository. Re-run the script to refresh them from upstream (filtering and deduplication are automatic):

```powershell
python fetch_wordlists.py
```

Generate a personalized wordlist (names, phone numbers, birthdays, street names...):

```powershell
python gen_wordlist.py --words "trung,nguyenthanhtrung,edufocus" --numbers "0912345678,15082000"
python gen_wordlist.py --words-file tokens.txt --numbers 0912345678 --pairs
```

Download additional global wordlists (optional — keep the exact filenames so `crack.py` picks them up automatically):

```powershell
curl.exe -L -o wordlists/rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
curl.exe -L -o wordlists/top-1m.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
```

### Wordlist sources (verified)

| Source | Contents | Notes |
|---|---|---|
| [polypores/vn-common-pass-dict](https://github.com/polypores/vn-common-pass-dict) | 418k Vietnamese WiFi passwords (WiFi Chùa source, 2021) | used by `fetch_wordlists.py` |
| [lucthienphong1120/wordlists-vi](https://github.com/lucthienphong1120/wordlists-vi) | Same WiFi list (identical md5) + `vn1m`/`vn10k` + a 20MB combined list | alternative mirror if the original link dies |
| [bateMD/wordlist-vn](https://github.com/bateMD/wordlist-vn) | VN names, birthdays, default creds, Voz usernames, 25MB all-in-one, hashcat rules | still updated in 2026; `fetch_wordlists.py` pulls dates + names |
| [conwnet/wpa-dictionary](https://github.com/conwnet/wpa-dictionary) | China-oriented WPA wordlist: birthdays ddmmyyyy (6MB), english, digits | useful birthday-pattern reference |
| [weakpass.com/wordlists/weakpass_2_wifi](https://weakpass.com/wordlists/weakpass_2_wifi) | Global aggregated WiFi wordlist | download via browser (direct links require JS) |
| [rockyou on weakpass](https://weakpass.com/wordlists/rockyou.txt) / `apt install wordlists` (Kali) | rockyou 14.3M | mirror when GitHub is slow |

> Lists originating from leaked data should only be used to **audit your own devices** and must not be redistributed. Default passwords on recent Viettel/VNPT/FPT routers are usually random strings printed on a sticker — wordlists cannot crack those, which is a good sign.

Results are stored in `cracked.potfile` and printed as:

```
[+] ĐÃ BẺ ĐƯỢC 1/1 hash
    SSID: TestWiFi  |  pass: 12345678
```

## Performance

Estimated runtimes on the reference GPU **GTX 1650 (~200 kH/s)**:

| Stage | Keyspace | Time |
|---|---|---|
| vn-wifi plain | 405k | ~2–4 seconds |
| personal + vn-common + dates + names | ~30k | a few seconds |
| best64 on the small lists | ~300k | a few seconds |
| best64 on vn-wifi | ~31M | ~2.5–4 minutes |
| top-1M plain | 1M | ~5–10 seconds |
| rockyou plain | 14.3M | ~1–2 minutes |
| 8 digits | 100M | ~8–15 minutes |
| VN phone numbers (`--phone`) | 500M | ~40–70 minutes |
| 9 digits | 1B | ~1.5–3 hours |
| rockyou + best64 (`--deep`) | ~1.1B | ~1.5–3 hours |

## Project structure

```
BruteForceWF/
├── audit.py              # End-to-end workflow: scan → capture → crack
├── crack.py              # hashcat mode 22000 orchestrator
├── gen_wordlist.py       # Personalized wordlist generator
├── fetch_wordlists.py    # Download + filter wordlists from public sources
├── ui.py                 # Rich UI (optional) + plain-text fallback
├── capture/
│   ├── pmkid.sh          # PMKID + EAPOL capture (hcxdumptool)
│   └── handshake.sh      # Handshake fallback (airodump-ng)
├── wordlists/            # Bundled Vietnamese wordlists
├── LICENSE               # MIT
└── README.md
```

## Technical notes

- **WPA3-only (SAE)**: this workflow does not apply — WPA3-SAE PMKID/EAPOL cannot be cracked with mode 22000. On routers configured for WPA2/WPA3 mixed mode, the WPA2 handshake is still captured normally.
- WPA-PSK requires **8–63 characters**, so every mask starts at length 8 and wordlists only contain candidates ≥ 8 characters (anything shorter is guaranteed wrong).
- Strong (long, random) passwords **cannot** be recovered — that is the point of the audit: if the tool finds your password quickly, it was weak.
- Failing to capture a PMKID does **not** mean the AP is safe; try the handshake. If the handshake cannot be captured either, re-check the channel/BSSID/distance.
- hcxdumptool's `--tot` is expressed in **minutes**; Ctrl+C stops early and the file is preserved.
- After capture, scripts restore the card to **managed mode** (removing an auxiliary monitor interface such as `wlo1mon` if present). `audit.py` restores NetworkManager automatically; if you run `capture/*.sh` standalone, run `sudo systemctl start NetworkManager` to regain connectivity.
- Speed tips: use an external card with an antenna and stand close to the AP during capture; for cracking, a discrete NVIDIA GPU is orders of magnitude faster than a CPU.

## Contributing

Pull requests and issues are welcome. Please open an issue to discuss significant changes before implementing them, and keep the project's core principle intact: this tool exists only to audit networks owned by its user.

## References

- hashcat WPA/WPA2 cracking: <https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2>
- hcxdumptool manpage: <https://manpages.debian.org/testing/hcxdumptool/hcxdumptool.1.en.html>
- hcxtools/hcxdumptool (ZerBea): <https://github.com/ZerBea/hcxtools>
- rockyou wordlist (SecLists): <https://github.com/danielmiessler/SecLists>

## License

[MIT](LICENSE) © 2026 Nguyễn Thành Trung — free to use, modify and distribute, provided the copyright notice is retained. The wordlists (`vn-wifi.txt`, `dates.txt`, `vn-names.txt`) originate from third-party public sources and follow their original licenses; **use them only to audit your own devices**.

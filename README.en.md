# BruteForceWF — audit your own WiFi password

[English](README.en.md) | [Tiếng Việt](README.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![hashcat](https://img.shields.io/badge/hashcat-%E2%89%A56.2-red.svg)](https://hashcat.net/hashcat/)

*Offline WPA/WPA2 password audit toolkit: PMKID/handshake capture + hashcat 22000 orchestrator, with Vietnamese wordlists.*

> **Use only on networks you own or have written authorization for.** Accessing someone else's WiFi is illegal (Vietnam: Article 289 of the Penal Code). This script exists to check whether your own home password is weak.

## How it works

WPA2 **cannot** be brute-forced "online" — every attempt requires a fresh 4-way handshake. The only viable approach:

1. **Capture** the PMKID or EAPOL handshake of the target network (Linux + a WiFi card with monitor mode support).
2. **Convert** it to hash format `22000`.
3. **Crack offline** with hashcat on a GPU — hundreds of thousands of password attempts per second.

## Quick start — one command

```bash
sudo python3 audit.py
```

The script scans every nearby AP (SSID, BSSID, channel, band, signal, security), lets you pick one by index, then captures PMKID + EAPOL with `hcxdumptool`, falls back to a handshake if no usable hash was produced, filters hashes down to the target BSSID, and invokes `crack.py`. Your WiFi is temporarily interrupted during capture and restored afterwards (NetworkManager).

Options: `--iface wlo1`, `--pmkid-minutes 5`, `--hs-seconds 60`, `--mask-lens 8,9`, `--phone`, `--deep`, `--wordlist <file>`, `--yes` (skip the network-ownership confirmation).

Before capturing, the script checks that `hashcat -I` reports an OpenCL/CUDA backend, and validates arguments and wordlists (relative paths are resolved against the current directory).

## Requirements

| Part | What you need |
|---|---|
| Crack (Windows) | hashcat ≥ 6.2 + NVIDIA driver. Tested machine: GTX 1650 4GB ≈ **150–250 kH/s** |
| Convert | hcxtools (`hcxpcapngtool`) — win64 build available, or convert on Linux |
| Capture | Any Linux (Ubuntu/Debian/Kali/Arch...) + a WiFi card supporting **monitor mode + packet injection**. External cards: Alfa AWUS036ACM/ACH. Most laptop cards work under Linux. |
| Linux tools | `hcxdumptool` ≥ 6.3, `hcxtools`, `aircrack-ng` |

> Kali is not required. Ubuntu/Debian: `sudo apt install aircrack-ng hcxdumptool hcxtools` is enough. Arch: `sudo pacman -S aircrack-ng hcxdumptool hcxtools iw` (WiFi firmware: `linux-firmware`). Kali/live USB is only convenient because the tools and drivers are preinstalled. Intel cards (AX200/AX210) can do monitor mode but injection is poor — passive handshake capture still works, but for deauth/PMKID prefer MediaTek/Ralink/Atheros cards (e.g. Alfa).

> WSL2 + usbipd usually **cannot** do monitor mode (no cfg80211/mac80211 drivers in the WSL kernel) — use a live USB / dual-boot Linux instead.

## Step 1 — Capture (Linux)

Note the BSSID + channel of your AP (e.g. from `iw dev` / router admin / an `airodump-ng` scan).

### Option A — PMKID + EAPOL with hcxdumptool (clientless, try first)

```bash
sudo ./capture/pmkid.sh wlan0 5        # scan for 5 minutes, all channels
sudo ./capture/pmkid.sh wlan0 5 6      # or pin a channel
sudo ./capture/pmkid.sh wlan0 5 6c     # 6GHz: channel + band suffix (a=2.4, b=5, c=6)
sudo ./capture/pmkid.sh wlan0 5 6 AA:BB:CC:DD:EE:FF   # target AP only (recommended)
```

- A single `hcxdumptool` session both requests **PMKID** and captures **EAPOL** (active deauth/association); it stops early once a PMKID or a complete M1M2/M1M2M3 pair is captured.
- No connected client needed; PMKID only works against APs **vulnerable to the PMKID attack**, while EAPOL needs a client reconnect (hcxdumptool deauths automatically).
- Output: `captures/pmkid-*.pcapng` + `.hc22000` (auto-converted when `hcxpcapngtool` is available); file mode `600`, `captures/` mode `700`.
- Pass a BSSID to capture only the target AP (BPF `wlan addr3`) — avoids polluting results with neighbours' hashes.
- The script adapts to the hcxdumptool version: from **6.3** it uses `-w`/`--rds` and `-c` with band suffix (`40` → `40b`, 6GHz uses `c`); older versions use `-o`/`--enable_status`.

### Option B — Handshake fallback with airodump (when Option A yields no hash)

```bash
sudo ./capture/handshake.sh wlan0 AA:BB:CC:DD:EE:FF 6
# include a client MAC to deauth the right target:
sudo ./capture/handshake.sh wlan0 AA:BB:CC:DD:EE:FF 6 11:22:33:44:55:66 60
# 6GHz: append the band (2.4 / 5 / 6):
sudo ./capture/handshake.sh wlan0 AA:BB:CC:DD:EE:FF 5 "" 60 6
```

- The script runs `airodump-ng` + short deauth bursts to force clients to reconnect (your network only), and stops once `hcxpcapngtool` produces a hash; if the dump is missing frames (aircrack-ng false positive), it keeps waiting and retries within the remaining time.
- Devices with PMF/802.11w enabled may ignore deauth — in that case just wait for the client to reconnect on its own.
- Output: `captures/hs-*.hc22000`.

Copy the `.hc22000` file to Windows (`scp` / USB).

## Step 2 — Convert (if you don't have a .hc22000)

```bash
hcxpcapngtool -o capture.hc22000 capture.pcapng
```
Run it on Linux, or use `hcxpcapngtool.exe` (hcxtools win64) on Windows. `crack.py` converts automatically when you pass a pcap file and the tool is in PATH.

## Step 3 — Crack (Windows)

Install hashcat: download from <https://hashcat.net/hashcat/>, extract (e.g. `C:\hashcat`), add it to PATH or pass `--hashcat`. On Arch: `sudo pacman -S hashcat opencl-nvidia` + an NVIDIA driver (`nvidia-open` for GTX 1650 and newer, or `nvidia`); verify with `hashcat -I`.

```powershell
python crack.py captures\hs-20261114-203000.hc22000
```

Default attack chain (stops as soon as the password is cracked):

1. **Dictionary** — `personal.txt` (if present) → `vn-wifi.txt` (~405k) → `vn-common.txt` (~3.4k) → `dates.txt` → `vn-names.txt` → `rockyou.txt`/`top-1m.txt` (if present)
2. **best64 rules** — mutations of the smaller wordlists; rockyou/top-1M only run with `--deep`
3. **Numeric masks** — 8 digits by default; `--mask-lens 8,9` adds 9 digits; `--phone` adds a 10-digit VN phone mask
4. **Hybrid** (`--deep` only) — `vn-base.txt`/`personal.txt` + 3–4 trailing digits (`matkhau123`)

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
| `vn-wifi.txt` | **405k real Vietnamese WiFi passwords** (from the WiFi Chùa app, public leak), filtered to 8–63 chars + deduped |
| `vn-common.txt` | ~3.4k curated common VN passwords (ISP, router, words + numeric suffixes), **≥ 8 chars** |
| `dates.txt` | 20.8k birthdays as `DDMMYYYY` (1970–2026) |
| `vn-names.txt` | 2k Vietnamese name combinations ≥ 8 chars |
| `vn-base.txt` | short base words, used for rules/hybrid |
| `personal.txt` | generated by `gen_wordlist.py` from your own info — the most effective list; used automatically if present |

The first 3 lists are included in the repo. Re-run the script to refresh them from upstream (filter + dedupe are automatic):

```powershell
python fetch_wordlists.py
```

Generate a personalized wordlist (names, phone numbers, birthdays, street names...):

```powershell
python gen_wordlist.py --words "trung,nguyenthanhtrung,edufocus" --numbers "0912345678,15082000"
python gen_wordlist.py --words-file tokens.txt --numbers 0912345678 --pairs
```

Download additional global wordlists (optional, keep the exact filenames so crack.py picks them up automatically):

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
| [conwnet/wpa-dictionary](https://github.com/conwnet/wpa-dictionary) | China-oriented WPA dict: birthdays ddmmyyyy (6MB), english, digits | useful birthday-pattern reference |
| [weakpass.com/wordlists/weakpass_2_wifi](https://weakpass.com/wordlists/weakpass_2_wifi) | Global aggregated WiFi wordlist | download via browser (direct links require JS) |
| [rockyou on weakpass](https://weakpass.com/wordlists/rockyou.txt) / `apt install wordlists` (Kali) | rockyou 14.3M | mirror when GitHub is slow |

Note: leaked lists are for **auditing your own devices**, not for redistribution. Default passwords on recent Viettel/VNPT/FPT routers are usually random strings printed on a sticker — wordlists can't crack those, which is a good sign.

Results are stored in `cracked.potfile` and printed as:

```
[+] ĐÃ BẺ ĐƯỢC 1/1 hash
    SSID: TestWiFi  |  pass: 12345678
```

## Time estimates (GTX 1650, ~200 kH/s)

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

## Technical notes

- **WPA3-only (SAE)**: this workflow does not apply — WPA3-SAE PMKID/EAPOL cannot be cracked with mode 22000. If the router runs WPA2/WPA3 mixed mode, the WPA2 handshake is still capturable.
- WPA-PSK requires **8–63 characters**, so every mask starts at length 8 and wordlists only contain candidates ≥ 8 (anything shorter is guaranteed wrong).
- Strong (long, random) passwords **cannot** be cracked — that is the point of the audit: if this script recovers your password quickly, it was weak.
- No PMKID ≠ safe AP; try the handshake. No handshake either? Check channel/BSSID/distance.
- hcxdumptool's `--tot` is in **minutes**; Ctrl+C stops early and keeps the file.
- After capture, scripts restore the card to **managed mode** (removing an auxiliary monitor iface such as `wlo1mon` if present). `audit.py` also restarts NetworkManager; if you run `capture/*.sh` standalone, run `sudo systemctl start NetworkManager` to get connectivity back.
- Speed tips: external card with an antenna, stand close to the AP; for cracking, a discrete NVIDIA GPU is orders of magnitude faster than a CPU.

## References

- hashcat WPA/WPA2 cracking: <https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2>
- hcxdumptool manpage: <https://manpages.debian.org/testing/hcxdumptool/hcxdumptool.1.en.html>
- hcxtools/hcxdumptool (ZerBea): <https://github.com/ZerBea/hcxtools>
- rockyou wordlist (SecLists): <https://github.com/danielmiessler/SecLists>

## License

[MIT](LICENSE) © 2026 Nguyễn Thành Trung — free to use, modify and distribute, provided the copyright notice is retained. The wordlists (`vn-wifi.txt`, `dates.txt`, `vn-names.txt`) come from third-party public sources and follow their original licenses; **use them only to audit your own devices**.

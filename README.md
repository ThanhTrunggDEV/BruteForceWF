# BruteForceWF

[English](README.en.md) | **Tiếng Việt**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![hashcat](https://img.shields.io/badge/hashcat-%E2%89%A56.2-red.svg)](https://hashcat.net/hashcat/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#đóng-góp)

**BruteForceWF** là bộ công cụ audit bảo mật WiFi dành cho mạng của chính bạn: quét các điểm truy cập xung quanh, capture PMKID hoặc EAPOL handshake, và crack offline bằng hashcat trên GPU. Dự án đi kèm bộ wordlist tiếng Việt được tuyển chọn theo thói quen đặt mật khẩu tại Việt Nam.

> [!WARNING]
> **Chỉ sử dụng trên mạng bạn sở hữu hoặc được uỷ quyền bằng văn bản.** Truy cập WiFi của người khác là hành vi vi phạm pháp luật (tại Việt Nam: Điều 289 Bộ luật Hình sự). Mục đích duy nhất của công cụ này là kiểm tra xem mật khẩu mạng nhà bạn có đủ mạnh hay không.

## Mục lục

- [Tính năng](#tính-năng)
- [Cách hoạt động](#cách-hoạt-động)
- [Yêu cầu hệ thống](#yêu-cầu-hệ-thống)
- [Bắt đầu nhanh](#bắt-đầu-nhanh)
- [Sử dụng](#sử-dụng)
- [Wordlist](#wordlist)
- [Hiệu năng](#hiệu-năng)
- [Cấu trúc dự án](#cấu-trúc-dự-án)
- [Ghi chú kỹ thuật](#ghi-chú-kỹ-thuật)
- [Đóng góp](#đóng-góp)
- [Tài liệu tham khảo](#tài-liệu-tham-khảo)
- [License](#license)

## Tính năng

- **Quy trình trọn vẹn trong một lệnh** — `audit.py` quét AP, cho chọn mục tiêu, capture và crack tự động.
- **Capture kép** — PMKID và EAPOL trong cùng một phiên `hcxdumptool`, tự fallback sang handshake bằng `airodump-ng` khi chưa thu được hash hợp lệ.
- **Chuyển đổi tự động** — PCAP/PCAPNG sang định dạng hashcat mode `22000` bằng `hcxpcapngtool`.
- **Điều phối hashcat nhiều tầng** — dictionary, rules, mask số và hybrid, dừng ngay khi bẻ được mật khẩu.
- **Wordlist tiếng Việt** — 405 nghìn mật khẩu WiFi thực tế, ngày sinh, tên riêng và mật khẩu phổ biến.
- **Wordlist cá nhân hoá** — `gen_wordlist.py` sinh biến thể từ tên, số điện thoại, ngày sinh của chính bạn.
- **Đa nền tảng** — capture trên mọi bản Linux; crack trên Windows hoặc Linux.

## Cách hoạt động

WPA2 **không thể** brute-force kiểu "thử từng mật khẩu online": mỗi lần thử đều cần một 4-way handshake mới. Cách tiếp cận khả thi duy nhất là crack offline:

```
Quét AP  →  Capture  →  Convert  →  Crack
Linux       PMKID/EAPOL  .hc22000    hashcat (GPU)
            handshake    (22000)
```

1. **Capture** PMKID hoặc EAPOL handshake của mạng mục tiêu (Linux + card WiFi hỗ trợ monitor mode).
2. **Convert** sang định dạng hash `22000`.
3. **Crack offline** bằng hashcat trên GPU — hàng trăm nghìn phép thử mỗi giây.

## Yêu cầu hệ thống

| Thành phần | Yêu cầu |
|---|---|
| Crack (Windows) | hashcat ≥ 6.2 + driver NVIDIA. Máy tham chiếu: GTX 1650 4GB ≈ **150–250 kH/s** |
| Convert | hcxtools (`hcxpcapngtool`) — có bản win64, hoặc convert trên Linux |
| Capture | Bất kỳ bản Linux nào (Ubuntu/Debian/Kali/Arch...) + card WiFi hỗ trợ **monitor mode + packet injection**. Card rời: Alfa AWUS036ACM/ACH; card laptop chạy Linux thường đáp ứng được. |
| Công cụ trên Linux | `hcxdumptool` ≥ 6.3, `hcxtools`, `aircrack-ng` |

Cài đặt:

```bash
# Ubuntu / Debian
sudo apt install aircrack-ng hcxdumptool hcxtools

# Arch Linux
sudo pacman -S aircrack-ng hcxdumptool hcxtools iw
```

> Không cần Kali — Kali/live USB chỉ tiện vì có sẵn công cụ và driver. Card Intel (AX200/AX210) có thể monitor mode nhưng khả năng injection kém: vẫn bắt handshake thụ động được, còn deauth/PMKID nên dùng card MediaTek/Ralink/Atheros (ví dụ Alfa).

> WSL2 + usbipd thường **không** chạy được monitor mode (kernel WSL thiếu driver cfg80211/mac80211) — hãy dùng live USB hoặc dual-boot Linux.

## Bắt đầu nhanh

```bash
sudo python3 audit.py
```

`audit.py` thực hiện toàn bộ quy trình: quét các AP xung quanh (SSID, BSSID, kênh, band, signal, bảo mật), cho chọn mục tiêu theo số thứ tự, capture PMKID + EAPOL bằng `hcxdumptool`, fallback handshake nếu chưa đủ hash, lọc hash theo đúng BSSID mục tiêu rồi gọi `crack.py`. WiFi của máy sẽ tạm ngắt trong lúc capture và được khôi phục sau đó (NetworkManager).

Các tuỳ chọn chính:

```bash
sudo python3 audit.py --iface wlo1          # chỉ định interface
sudo python3 audit.py --pmkid-minutes 5     # thời gian capture PMKID
sudo python3 audit.py --hs-seconds 60       # thời gian fallback handshake
sudo python3 audit.py --mask-lens 8,9 --phone --deep
sudo python3 audit.py --wordlist custom.txt
sudo python3 audit.py --yes                 # bỏ xác nhận sở hữu mạng
```

Trước khi capture, script kiểm tra `hashcat -I` có backend OpenCL/CUDA, đồng thời validate tham số và wordlist (đường dẫn tương đối được resolve theo thư mục hiện tại).

## Sử dụng

### 1. Capture (Linux)

Ghi lại BSSID và kênh của AP mục tiêu (từ `iw dev`, trang quản trị router hoặc quét bằng `airodump-ng`).

#### PMKID + EAPOL bằng hcxdumptool (clientless, ưu tiên thử trước)

```bash
sudo ./capture/pmkid.sh wlan0 5        # quét 5 phút, mọi kênh
sudo ./capture/pmkid.sh wlan0 5 6      # hoặc chỉ định kênh
sudo ./capture/pmkid.sh wlan0 5 6c     # 6GHz: kênh + hậu tố band (a=2.4, b=5, c=6)
sudo ./capture/pmkid.sh wlan0 5 6 AA:BB:CC:DD:EE:FF   # chỉ AP mục tiêu (khuyến nghị)
```

- Một phiên `hcxdumptool` vừa yêu cầu **PMKID** vừa bắt **EAPOL** (deauth/association chủ động); script dừng sớm khi đã có PMKID hoặc cặp M1M2/M1M2M3 hoàn chỉnh.
- Không cần client đang kết nối. PMKID chỉ hiệu quả với AP còn tồn tại lỗ hổng PMKID; EAPOL cần client reconnect (hcxdumptool tự deauth).
- Kết quả: `captures/pmkid-*.pcapng` + `.hc22000` (tự convert nếu có `hcxpcapngtool`); file có quyền `600`, thư mục `captures/` quyền `700`.
- Truyền BSSID để chỉ capture AP mục tiêu (BPF `wlan addr3`), tránh lẫn hash của các AP lân cận.
- Script tự thích ứng phiên bản hcxdumptool: từ **6.3** dùng `-w`/`--rds` và `-c` kèm hậu tố band (`40` → `40b`, 6GHz dùng `c`); bản cũ hơn dùng `-o`/`--enable_status`.

#### Handshake fallback bằng airodump-ng

```bash
sudo ./capture/handshake.sh wlan0 AA:BB:CC:DD:EE:FF 6
# kèm MAC client để deauth đúng mục tiêu:
sudo ./capture/handshake.sh wlan0 AA:BB:CC:DD:EE:FF 6 11:22:33:44:55:66 60
# 6GHz: thêm band ở cuối (2.4 / 5 / 6):
sudo ./capture/handshake.sh wlan0 AA:BB:CC:DD:EE:FF 5 "" 60 6
```

- Script chạy `airodump-ng` kèm các đợt deauth ngắn để ép client reconnect (chỉ mạng của bạn) và tự dừng khi `hcxpcapngtool` tạo được hash. Nếu capture thiếu frame (aircrack-ng báo nhầm handshake), script tiếp tục chờ và thử lại trong thời gian còn lại.
- Thiết bị bật PMF/802.11w có thể bỏ qua deauth — khi đó chỉ cần chờ client tự kết nối lại.
- Kết quả: `captures/hs-*.hc22000`.

Sau khi capture, copy file `.hc22000` sang máy Windows (`scp` hoặc USB).

### 2. Convert (nếu chưa có .hc22000)

```bash
hcxpcapngtool -o capture.hc22000 capture.pcapng
```

Chạy trên Linux hoặc dùng `hcxpcapngtool.exe` (hcxtools win64) trên Windows. `crack.py` tự convert khi bạn truyền file pcap và công cụ nằm trong PATH.

### 3. Crack (Windows / Linux)

Cài hashcat: tải tại <https://hashcat.net/hashcat/>, giải nén (ví dụ `C:\hashcat`), thêm vào PATH hoặc truyền `--hashcat`. Trên Arch: `sudo pacman -S hashcat opencl-nvidia` kèm driver NVIDIA (`nvidia-open` cho GTX 1650 trở lên, hoặc `nvidia`); kiểm tra bằng `hashcat -I`.

```powershell
python crack.py captures\hs-20261114-203000.hc22000
```

Chuỗi tấn công mặc định (dừng ngay khi bẻ được mật khẩu):

1. **Dictionary** — `personal.txt` (nếu có) → `vn-wifi.txt` (~405k) → `vn-common.txt` (~3.4k) → `dates.txt` → `vn-names.txt` → `rockyou.txt`/`top-1m.txt` (nếu có).
2. **Rules best64** — biến thể của các wordlist nhỏ; rockyou/top-1M chỉ chạy khi bật `--deep`.
3. **Mask số** — mặc định 8 chữ số; `--mask-lens 8,9` thêm độ dài 9; `--phone` thêm mask số điện thoại Việt Nam (10 chữ số).
4. **Hybrid** — chỉ với `--deep`: `vn-base.txt`/`personal.txt` kết hợp 3–4 chữ số cuối (ví dụ `matkhau123`).

Các tuỳ chọn khác:

```powershell
python crack.py capture.hc22000 --dry-run          # xem kế hoạch, không chạy
python crack.py capture.hc22000 --show-only        # in mật khẩu đã crack trong potfile
python crack.py capture.hc22000 --phone            # thêm mask số điện thoại VN
python crack.py capture.hc22000 --deep             # thêm rockyou+best64, hybrid (lâu)
python crack.py capture.hc22000 --wordlist C:\lists\custom.txt --mask-lens 8,9
```

## Wordlist

| File | Nội dung |
|---|---|
| `vn-wifi.txt` | **405k mật khẩu WiFi Việt thực tế** (từ app WiFi Chùa, dữ liệu công khai), đã lọc 8–63 ký tự và dedupe |
| `vn-common.txt` | ~3.4k mật khẩu phổ biến tại Việt Nam được biên soạn thủ công (ISP, router, từ + hậu tố số), **≥ 8 ký tự** |
| `dates.txt` | 20.8k ngày sinh dạng `DDMMYYYY` (1970–2026) |
| `vn-names.txt` | 2k tổ hợp tên Việt Nam ≥ 8 ký tự |
| `vn-base.txt` | từ gốc ngắn, dùng cho rules/hybrid |
| `personal.txt` | sinh bằng `gen_wordlist.py` từ thông tin của chính bạn — hiệu quả nhất; được tự động sử dụng nếu tồn tại |

Ba danh sách đầu đã có sẵn trong repo. Chạy lại script để cập nhật từ nguồn (tự động lọc và dedupe):

```powershell
python fetch_wordlists.py
```

Sinh wordlist cá nhân hoá (tên, số điện thoại, ngày sinh, tên đường...):

```powershell
python gen_wordlist.py --words "trung,nguyenthanhtrung,edufocus" --numbers "0912345678,15082000"
python gen_wordlist.py --words-file tokens.txt --numbers 0912345678 --pairs
```

Tải thêm wordlist toàn cầu (tuỳ chọn — đặt đúng tên để `crack.py` tự động sử dụng):

```powershell
curl.exe -L -o wordlists/rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
curl.exe -L -o wordlists/top-1m.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
```

### Nguồn wordlist (đã kiểm chứng)

| Nguồn | Nội dung | Ghi chú |
|---|---|---|
| [polypores/vn-common-pass-dict](https://github.com/polypores/vn-common-pass-dict) | 418k mật khẩu WiFi Việt (nguồn WiFi Chùa, 2021) | được `fetch_wordlists.py` sử dụng |
| [lucthienphong1120/wordlists-vi](https://github.com/lucthienphong1120/wordlists-vi) | Cùng danh sách WiFi (trùng md5) + `vn1m`/`vn10k` + bản combine 20MB | mirror thay thế nếu link gốc không còn |
| [bateMD/wordlist-vn](https://github.com/bateMD/wordlist-vn) | Tên Việt, ngày sinh, default creds, username Voz, bản all-in-one 25MB, hashcat rules | vẫn được cập nhật trong 2026; `fetch_wordlists.py` lấy dates + names |
| [conwnet/wpa-dictionary](https://github.com/conwnet/wpa-dictionary) | Wordlist WPA hướng Trung Quốc: ngày sinh ddmmyyyy (6MB), english, digits | tham khảo cho pattern ngày sinh |
| [weakpass.com/wordlists/weakpass_2_wifi](https://weakpass.com/wordlists/weakpass_2_wifi) | Wordlist WiFi tổng hợp toàn cầu | tải qua trình duyệt (link trực tiếp yêu cầu JS) |
| [rockyou trên weakpass](https://weakpass.com/wordlists/rockyou.txt) / `apt install wordlists` (Kali) | rockyou 14.3M | mirror khi GitHub chậm |

> Các danh sách có nguồn gốc từ dữ liệu rò rỉ chỉ nên dùng để **audit thiết bị của chính bạn**, không phân phối lại. Mật khẩu mặc định của router Viettel/VNPT/FPT đời mới thường là chuỗi ngẫu nhiên in trên tem — wordlist gần như không bẻ được, và đó là dấu hiệu tốt.

Kết quả được lưu trong `cracked.potfile` và in ra dạng:

```
[+] ĐÃ BẺ ĐƯỢC 1/1 hash
    SSID: TestWiFi  |  pass: 12345678
```

## Hiệu năng

Ước lượng thời gian trên GPU tham chiếu **GTX 1650 (~200 kH/s)**:

| Giai đoạn | Keyspace | Thời gian |
|---|---|---|
| vn-wifi plain | 405k | ~2–4 giây |
| personal + vn-common + dates + names | ~30k | vài giây |
| best64 trên các list nhỏ | ~300k | vài giây |
| best64 trên vn-wifi | ~31M | ~2.5–4 phút |
| top-1M plain | 1M | ~5–10 giây |
| rockyou plain | 14.3M | ~1–2 phút |
| 8 chữ số | 100M | ~8–15 phút |
| Số điện thoại VN (`--phone`) | 500M | ~40–70 phút |
| 9 chữ số | 1B | ~1.5–3 giờ |
| rockyou + best64 (`--deep`) | ~1.1B | ~1.5–3 giờ |

## Cấu trúc dự án

```
BruteForceWF/
├── audit.py              # Quy trình trọn vẹn: quét → capture → crack
├── crack.py              # Orchestrator hashcat mode 22000
├── gen_wordlist.py       # Sinh wordlist cá nhân hoá
├── fetch_wordlists.py    # Tải + lọc wordlist từ nguồn công khai
├── capture/
│   ├── pmkid.sh          # Capture PMKID + EAPOL (hcxdumptool)
│   └── handshake.sh      # Fallback handshake (airodump-ng)
├── wordlists/            # Wordlist tiếng Việt đóng gói sẵn
├── LICENSE               # MIT
└── README.md
```

## Ghi chú kỹ thuật

- **WPA3-only (SAE)**: quy trình này không áp dụng — PMKID/EAPOL của WPA3-SAE không crack được bằng mode 22000. Với router cấu hình WPA2/WPA3 mixed, handshake WPA2 vẫn bắt được bình thường.
- WPA-PSK yêu cầu **8–63 ký tự**, nên mọi mask bắt đầu từ độ dài 8 và wordlist chỉ chứa ứng viên ≥ 8 ký tự (ngắn hơn chắc chắn sai).
- Mật khẩu mạnh (dài, ngẫu nhiên) **không thể bẻ được** — đó chính là mục đích của audit: nếu công cụ tìm ra mật khẩu nhanh, mật khẩu của bạn đang yếu.
- Không bắt được PMKID **không** đồng nghĩa AP an toàn; hãy thử handshake. Nếu handshake cũng không bắt được, kiểm tra lại kênh/BSSID/khoảng cách.
- `--tot` của hcxdumptool tính bằng **phút**; Ctrl+C dừng sớm và file vẫn được giữ nguyên.
- Sau capture, script tự đưa card về **managed mode** (xoá interface monitor phụ như `wlo1mon` nếu có). `audit.py` khôi phục NetworkManager tự động; nếu chạy riêng `capture/*.sh`, hãy chạy `sudo systemctl start NetworkManager` để có mạng trở lại.
- Tăng tốc: dùng card rời có anten và đứng gần AP khi capture; khi crack, GPU NVIDIA rời nhanh hơn CPU hàng chục lần.

## Đóng góp

Mọi pull request và issue đều được hoan nghênh. Vui lòng mở issue để thảo luận trước khi thực hiện các thay đổi lớn, và giữ nguyên nguyên tắc của dự án: công cụ chỉ phục vụ audit mạng thuộc sở hữu của chính người dùng.

## Tài liệu tham khảo

- hashcat WPA/WPA2 cracking: <https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2>
- hcxdumptool manpage: <https://manpages.debian.org/testing/hcxdumptool/hcxdumptool.1.en.html>
- hcxtools/hcxdumptool (ZerBea): <https://github.com/ZerBea/hcxtools>
- rockyou wordlist (SecLists): <https://github.com/danielmiessler/SecLists>

## License

[MIT](LICENSE) © 2026 Nguyễn Thành Trung — tự do sử dụng, chỉnh sửa và phân phối, với điều kiện giữ nguyên copyright notice. Các wordlist (`vn-wifi.txt`, `dates.txt`, `vn-names.txt`) có nguồn gốc từ bên thứ ba công khai và tuân theo license gốc của nguồn; **chỉ sử dụng để audit thiết bị của chính bạn**.

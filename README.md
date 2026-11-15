# BruteForceWF — audit mật khẩu WiFi của chính bạn

> **Chỉ dùng cho mạng bạn sở hữu hoặc có uỷ quyền bằng văn bản.** Truy cập WiFi của người khác là vi phạm pháp luật (VN: Điều 289 Bộ luật Hình sự). Script này để tự kiểm tra mật khẩu nhà mình có yếu không.

## Cách hoạt động

WPA2 **không thể** brute-force kiểu "thử từng mật khẩu online" — mỗi lần thử cần một 4-way handshake mới. Cách duy nhất khả thi:

1. **Capture** PMKID hoặc EAPOL handshake của mạng mục tiêu (Linux + card WiFi hỗ trợ monitor mode).
2. **Convert** sang định dạng hash `22000`.
3. **Crack offline** bằng hashcat trên GPU — thử hàng trăm nghìn mật khẩu/giây.

## Quy trình nhanh — một lệnh

```bash
sudo python3 audit.py
```

Script quét toàn bộ AP xung quanh (SSID, BSSID, kênh, band, signal, bảo mật), cho chọn STT, rồi tự thử PMKID → handshake, lọc hash đúng BSSID mục tiêu và gọi `crack.py`. WiFi của máy ngắt tạm thời trong lúc capture và được bật lại sau (NetworkManager).

Tuỳ chọn: `--iface wlo1`, `--pmkid-minutes 5`, `--hs-seconds 60`, `--mask-lens 8,9`, `--phone`, `--deep`, `--wordlist <file>`, `--yes` (bỏ xác nhận sở hữu mạng).

Trước khi capture, script kiểm tra `hashcat -I` có backend OpenCL/CUDA, validate tham số và wordlist (đường dẫn tương đối được resolve theo thư mục hiện tại).

## Yêu cầu

| Phần | Cần gì |
|---|---|
| Crack (Windows) | hashcat ≥ 6.2 + driver NVIDIA. Máy này: GTX 1650 4GB ≈ **150–250 kH/s** |
| Convert | hcxtools (`hcxpcapngtool`) — có bản win64, hoặc convert trên Linux |
| Capture | Bất kỳ Linux nào (Ubuntu/Debian/Kali/Arch...) + card WiFi hỗ trợ **monitor mode + packet injection**. Card rời: Alfa AWUS036ACM/ACH. Card laptop chạy Linux thường ổn. |
| Tool trên Linux | `hcxdumptool` ≥ 6.3, `hcxtools`, `aircrack-ng` |

> Không cần Kali. Ubuntu/Debian: `sudo apt install aircrack-ng hcxdumptool hcxtools` là đủ. Arch: `sudo pacman -S aircrack-ng hcxdumptool hcxtools iw` (firmware WiFi: `linux-firmware`). Kali/live USB chỉ tiện vì có sẵn tool + driver. Card Intel (AX200/AX210) monitor mode được nhưng injection kém — vẫn bắt handshake thụ động được, còn deauth/PMKID thì nên dùng card MediaTek/Ralink/Atheros (vd Alfa).

> WSL2 + usbipd thường **không** chạy được monitor mode (thiếu driver cfg80211/mac80211 trong kernel WSL) — dùng live USB/dual-boot Linux cho chắc.

## Bước 1 — Capture (Linux)

Ghi lại BSSID + kênh của AP nhà mày (ví dụ từ `iw dev` / router admin / `airodump-ng` quét).

### Cách A — PMKID (clientless, thử trước)

```bash
sudo ./capture/pmkid.sh wlan0 5        # quét 5 phút, mọi kênh
sudo ./capture/pmkid.sh wlan0 5 6      # hoặc chỉ định kênh
sudo ./capture/pmkid.sh wlan0 5 6c     # 6GHz: kênh + band c (a=2.4, b=5, c=6)
sudo ./capture/pmkid.sh wlan0 5 6 AA:BB:CC:DD:EE:FF   # chỉ AP mục tiêu (khuyến nghị)
```

- Không cần client đang kết nối, nhưng **chỉ ăn với AP còn dính lỗi PMKID** (nhiều router ISP cũ).
- Kết quả: `captures/pmkid-*.pcapng` + `.hc22000` (tự convert nếu có `hcxpcapngtool`); file `600`, thư mục `captures/` `700`.
- Truyền BSSID để chỉ capture AP mục tiêu (BPF `wlan addr3`, tự thoát khi có EAPOL) — tránh lẫn hash hàng xóm.
- Script tự thích ứng hcxdumptool: từ **6.3** dùng `-w`/`--rds` và `-c` kèm hậu tố band (`40` → `40b`, 6GHz dùng `c`); bản cũ hơn dùng `-o`/`--enable_status`.

### Cách B — Handshake (cần client đang/ sắp kết nối)

```bash
sudo ./capture/handshake.sh wlan0 AA:BB:CC:DD:EE:FF 6
# kèm MAC client để deauth đúng mục tiêu:
sudo ./capture/handshake.sh wlan0 AA:BB:CC:DD:EE:FF 6 11:22:33:44:55:66 60
# 6GHz: thêm band ở cuối (2.4 / 5 / 6):
sudo ./capture/handshake.sh wlan0 AA:BB:CC:DD:EE:FF 5 "" 60 6
```

- Script chạy `airodump-ng` + deauth ngắn để ép client reconnect (chỉ mạng của mày), tự dừng khi `hcxpcapngtool` tạo được hash; nếu dump thiếu frame (aircrack-ng báo nhầm handshake) sẽ chờ thêm và thử lại trong thời gian còn lại.
- Thiết bị bật PMF/802.11w có thể bỏ qua deauth — khi đó chờ client tự kết nối lại.
- Kết quả: `captures/hs-*.hc22000`.

Copy file `.hc22000` sang Windows (`scp` / USB).

## Bước 2 — Convert (nếu chưa có .hc22000)

```bash
hcxpcapngtool -o capture.hc22000 capture.pcapng
```
Chạy trên Linux, hoặc dùng `hcxpcapngtool.exe` (hcxtools win64) trên Windows. `crack.py` tự convert nếu bạn truyền file pcap và tool nằm trong PATH.

## Bước 3 — Crack (Windows)

Cài hashcat: tải tại <https://hashcat.net/hashcat/>, giải nén (vd `C:\hashcat`), thêm vào PATH hoặc dùng `--hashcat`. Trên Arch: `sudo pacman -S hashcat opencl-nvidia` + driver NVIDIA (`nvidia-open` cho GTX 1650 trở lên, hoặc `nvidia`); kiểm tra bằng `hashcat -I`.

```powershell
python crack.py captures\hs-20261114-203000.hc22000
```

Chuỗi tấn công mặc định (dừng ngay khi bẻ được):

1. **Dictionary** — `personal.txt` (nếu có) → `vn-wifi.txt` (~405k) → `vn-common.txt` (~3.4k) → `dates.txt` → `vn-names.txt` → `rockyou.txt`/`top-1m.txt` (nếu có)
2. **Rules best64** — biến thể của wordlist nhỏ; rockyou/top-1M chỉ chạy với `--deep`
3. **Mask số** — mặc định 8 chữ số; `--mask-lens 8,9` để thêm 9 số; `--phone` thêm mask SĐT VN 10 số
4. **Hybrid** (chỉ với `--deep`) — `vn-base.txt`/`personal.txt` + 3–4 số cuối (`matkhau123`)

Tuỳ chọn khác:

```powershell
python crack.py capture.hc22000 --dry-run          # xem kế hoạch, không chạy
python crack.py capture.hc22000 --show-only        # in pass đã crack trong potfile
python crack.py capture.hc22000 --phone            # thêm mask số điện thoại VN
python crack.py capture.hc22000 --deep             # thêm rockyou+best64, hybrid (lâu)
python crack.py capture.hc22000 --wordlist C:\lists\custom.txt --mask-lens 8,9
```

## Wordlist

| File | Nội dung |
|---|---|
| `vn-wifi.txt` | **405k mật khẩu WiFi Việt thật** (từ app WiFi Chùa, leak công khai), đã lọc 8–63 ký tự + dedupe |
| `vn-common.txt` | ~3.4k mật khẩu phổ biến VN tự biên (ISP, router, từ + đuôi số), **≥ 8 ký tự** |
| `dates.txt` | 20.8k ngày sinh dạng `DDMMYYYY` (1970–2026) |
| `vn-names.txt` | 2k tổ hợp tên VN ≥ 8 ký tự |
| `vn-base.txt` | từ gốc ngắn, dùng cho rules/hybrid |
| `personal.txt` | sinh bằng `gen_wordlist.py` từ thông tin của chính bạn — hiệu quả nhất; tự động được dùng nếu tồn tại |

3 list đầu đã có sẵn trong repo. Chạy lại script khi muốn cập nhật từ nguồn (tự lọc + dedupe):

```powershell
python fetch_wordlists.py
```

Sinh wordlist cá nhân hoá (tên, SĐT, ngày sinh, tên đường...):

```powershell
python gen_wordlist.py --words "trung,nguyenthanhtrung,edufocus" --numbers "0912345678,15082000"
python gen_wordlist.py --words-file tokens.txt --numbers 0912345678 --pairs
```

Tải thêm wordlist toàn cầu (tuỳ chọn, đặt đúng tên để crack.py tự dùng):

```powershell
curl.exe -L -o wordlists/rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
curl.exe -L -o wordlists/top-1m.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
```

### Nguồn wordlist trên mạng (đã kiểm chứng)

| Nguồn | Nội dung | Ghi chú |
|---|---|---|
| [polypores/vn-common-pass-dict](https://github.com/polypores/vn-common-pass-dict) | 418k mật khẩu WiFi VN (nguồn WiFi Chùa, 2021) | `fetch_wordlists.py` dùng list này |
| [lucthienphong1120/wordlists-vi](https://github.com/lucthienphong1120/wordlists-vi) | Cùng list WiFi trên (trùng md5) + `vn1m`/`vn10k` + combine 20MB | bản sao thay thế nếu link gốc chết |
| [bateMD/wordlist-vn](https://github.com/bateMD/wordlist-vn) | Tên VN, ngày sinh, default creds, username Voz, all-in-one 25MB, hashcat rules | repo còn update 2026; `fetch_wordlists.py` lấy dates + names |
| [conwnet/wpa-dictionary](https://github.com/conwnet/wpa-dictionary) | WPA dict hướng Trung Quốc: birthday ddmmyyyy (6MB), english, digits | tham khảo pattern ngày sinh |
| [weakpass.com/wordlists/weakpass_2_wifi](https://weakpass.com/wordlists/weakpass_2_wifi) | wordlist WiFi tổng hợp toàn cầu | tải qua trình duyệt (link direct cần JS) |
| [rockyou trên weakpass](https://weakpass.com/wordlists/rockyou.txt) / `apt install wordlists` (Kali) | rockyou 14.3M | mirror khi GitHub chậm |

Lưu ý: các list từ leak dùng cho **audit máy mình**, không phân phối lại. Mật khẩu mặc định của router Viettel/VNPT/FPT đời mới thường là chuỗi random in trên tem — wordlist gần như không bẻ được, đó là dấu hiệu tốt.

Kết quả lưu trong `cracked.potfile`, in ra dạng:

```
[+] ĐÃ BẺ ĐƯỢC 1/1 hash
    SSID: TestWiFi  |  pass: 12345678
```

## Ước lượng thời gian (GTX 1650, ~200 kH/s)

| Giai đoạn | Keyspace | Thời gian |
|---|---|---|
| vn-wifi plain | 405k | ~2–4 giây |
| personal + vn-common + dates + names | ~30k | vài giây |
| best64 trên các list nhỏ | ~300k | vài giây |
| best64 trên vn-wifi | ~31M | ~2.5–4 phút |
| top-1M plain | 1M | ~5–10 giây |
| rockyou plain | 14.3M | ~1–2 phút |
| 8 chữ số | 100M | ~8–15 phút |
| SĐT VN (`--phone`) | 500M | ~40–70 phút |
| 9 chữ số | 1B | ~1.5–3 giờ |
| rockyou + best64 (`--deep`) | ~1.1B | ~1.5–3 giờ |

## Lưu ý kỹ thuật

- **WPA3-only (SAE)**: quy trình này không áp dụng — PMKID/EAPOL của WPA3-SAE không crack được bằng mode 22000. Nếu router để WPA2/WPA3 mixed thì handshake WPA2 vẫn bắt được.
- WPA-PSK yêu cầu **8–63 ký tự**, nên mọi mask bắt đầu từ 8 và wordlist chỉ chứa ứng viên ≥ 8 (ngắn hơn chắc chắn sai).
- Mật khẩu mạnh (dài, ngẫu nhiên) thì **không bẻ được** — đó chính là mục đích của audit: nếu script này ra pass nhanh, mật khẩu của mày đang yếu.
- PMKID không bắt được ≠ AP an toàn; thử handshake. Handshake không bắt được thì kiểm tra kênh/BSSID/khoảng cách.
- `--tot` của hcxdumptool tính bằng **phút**; Ctrl+C dừng sớm, file vẫn giữ.
- Sau capture, script tự đưa card về **managed mode** (xoá iface monitor phụ như `wlo1mon` nếu có). `audit.py` còn tự bật lại NetworkManager; nếu chạy `capture/*.sh` riêng thì chạy `sudo systemctl start NetworkManager` để có mạng lại.
- Tăng tốc: card rời gắn anten, đứng gần AP; crack thì GPU NVIDIA rời nhanh hơn CPU hàng chục lần.

## Nguồn tham khảo

- hashcat WPA/WPA2 cracking: <https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2>
- hcxdumptool manpage: <https://manpages.debian.org/testing/hcxdumptool/hcxdumptool.1.en.html>
- hcxtools/hcxdumptool (ZerBea): <https://github.com/ZerBea/hcxtools>
- rockyou wordlist (SecLists): <https://github.com/danielmiessler/SecLists>

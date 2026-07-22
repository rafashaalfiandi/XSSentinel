<div align="center">

<pre>
 __  __ ____ ____             _   _            _
 \ \/ // ___/ ___|  ___ _ __ | |_(_)_ __   ___| |
  \  / \___ \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
  /  \  ___) |__) |  __/ | | | |_| | | | |  __/ |
 /_/\_\|____/____/ \___|_| |_|\__|_|_| |_|\___|_|
</pre>

<h1>XSSentinel</h1>

<p><strong>Scanner XSS untuk pengujian resmi dengan payload fuzzing, analisis refleksi, validasi browser, deteksi API evidence, CSP check, WAF hint, dan analisis DOM sink.</strong></p>

<p>
  <a href="https://www.python.org/"><img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white"></a>
  <img alt="Platform" src="https://img.shields.io/badge/Platform-Linux-555555?style=flat-square">
  <img alt="Use" src="https://img.shields.io/badge/Use-Authorized%20Testing%20Only-d46a6a?style=flat-square">
</p>

</div>

## Ringkasan

XSSentinel membantu menguji reflected XSS, risiko DOM XSS, dan endpoint API yang merefleksikan payload. Tool ini dibuat untuk pengujian keamanan yang legal, jelas, dan mudah diaudit dari output terminal.

Fitur utama:

- Menguji parameter GET dan POST yang ditemukan dari target.
- Mode default menguji satu parameter per request agar parameter rentan lebih mudah dilacak.
- Mode opsional `--all-params` menguji semua query parameter sekaligus untuk satu endpoint.
- Smart payload selection untuk mencoba payload prioritas terlebih dahulu.
- Analisis konteks refleksi: HTML text, attribute, script, comment, raw/API response, dan konteks lain.
- Validasi browser menggunakan Chromium atau Playwright jika tersedia.
- Deteksi API evidence tanpa langsung menganggapnya valid sebelum ada bukti eksekusi browser.
- Output URL lengkap berisi payload untuk temuan `[VALID]` dan `[API]` agar mudah diretest manual.
- Deteksi CSP, sinyal WAF, JavaScript source, dan DOM sink.
- Worker paralel untuk endpoint/parameter yang ditemukan.

## Penggunaan Bertanggung Jawab

Gunakan XSSentinel hanya pada aplikasi yang kamu miliki atau yang kamu punya izin tertulis/eksplisit untuk diuji. Jangan menjalankan scan ke sistem pihak ketiga tanpa izin.

## Instalasi

```bash
git clone https://github.com/rafashaalfiandi/XSSentinel.git
cd XSSentinel
chmod +x install.sh
./install.sh
```

Setelah install, jalankan:

```bash
xssentinel -h
```

Jika command `xssentinel` belum terbaca, tambahkan `~/.local/bin` ke `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Untuk permanen, masukkan baris tersebut ke file shell seperti `~/.bashrc` atau `~/.zshrc`.

## Command Utama

```bash
xssentinel <url>
xssentinel --all-params <url>
xssentinel --stop-on-confirmed <url>
xssentinel
xssentinel -update
xssentinel -restart
xssentinel -h
```

Penjelasan:

| Command | Fungsi |
| --- | --- |
| `xssentinel <url>` | Scan target langsung dari command line. |
| `xssentinel` | Mode interaktif, tool akan meminta URL target. |
| `xssentinel --all-params <url>` | Mengirim payload yang sama ke semua query parameter dalam satu request. |
| `xssentinel --stop-on-confirmed <url>` | Berhenti total setelah temuan valid pertama. |
| `xssentinel -update` | Mengambil versi terbaru XSSentinel dan memasang ulang runtime command. |
| `xssentinel -restart` | Membersihkan cache lalu memasang ulang runtime dari source lokal yang tersimpan. Cocok setelah edit source lokal. |
| `xssentinel -h` | Menampilkan bantuan command. |

Catatan penting:

- Pakai `xssentinel -update` untuk memperbarui tool ke versi terbaru.
- Pakai `xssentinel -restart` setelah kamu mengedit file source lokal dan ingin command `xssentinel` memakai perubahan itu.
- `-restart` tidak mengambil update dari remote; hanya refresh runtime lokal.

## Contoh Penggunaan

Scan URL dengan satu parameter:

```bash
xssentinel "https://target.test/search?q=test"
```

Scan URL dengan banyak parameter. Secara default, tiap parameter diuji satu per satu:

```bash
xssentinel "https://target.test/artikel/search?query=test&kata=test&kunci=test&menu=test&category=test"
```

Scan semua query parameter sekaligus untuk endpoint yang sama:

```bash
xssentinel --all-params "https://target.test/artikel/search?query=test&kata=test&kunci=test&menu=test&category=test"
```

Berhenti total setelah XSS valid pertama ditemukan:

```bash
xssentinel --stop-on-confirmed "https://target.test/search?q=test"
```

Update tool:

```bash
xssentinel -update
```

Refresh runtime dari source lokal:

```bash
xssentinel -restart
```

## Mode Parameter

### Default: `single-param`

Mode default menguji satu parameter per request. Contoh target:

```text
https://target.test/search?query=test&kata=test&category=test
```

XSSentinel akan membuat request terpisah seperti:

```text
https://target.test/search?query=PAYLOAD&kata=test&category=test
https://target.test/search?query=test&kata=PAYLOAD&category=test
https://target.test/search?query=test&kata=test&category=PAYLOAD
```

Kelebihan mode ini:

- Lebih akurat untuk mengetahui parameter mana yang rentan.
- Lebih mudah dibuktikan dari URL hasil.
- Mengurangi noise dari endpoint yang sensitif terhadap banyak input berubah sekaligus.

### Opsional: `all-params`

Mode ini aktif dengan `--all-params`. Semua query parameter diisi payload yang sama dalam satu request.

Contoh:

```text
https://target.test/search?query=PAYLOAD&kata=PAYLOAD&category=PAYLOAD
```

Gunakan mode ini saat:

- Endpoint hanya bereaksi jika beberapa parameter berubah bersamaan.
- Ingin melihat apakah kombinasi parameter memicu sink tertentu.
- Ingin coverage cepat pada endpoint tertentu.

Output awal scan akan menampilkan mode aktif, misalnya:

```text
[INFO] scan-mode=single-param (one parameter is fuzzed per request)
[INFO] stop-policy=per-target-confirmed
```

atau:

```text
[INFO] scan-mode=all-params (all query parameters receive the same payload in each request)
[INFO] stop-policy=per-target-confirmed
```

## Cara XSSentinel Menentukan Hasil

XSSentinel tidak langsung menganggap semua refleksi sebagai XSS valid. Hasil dinilai dari beberapa lapisan:

- Apakah payload muncul kembali di response.
- Di konteks apa payload muncul: HTML, attribute, script, raw/API, dan lainnya.
- Apakah payload benar-benar mengeksekusi dialog di browser.
- Apakah response berupa API/download yang hanya mengirim payload, tetapi belum tentu dieksekusi frontend.

Marker hasil:

| Marker | Status | Arti |
| --- | --- | --- |
| `[VALID]` | `CONFIRMED` | Eksekusi sudah terkonfirmasi oleh browser/dialog evidence. |
| `[API]` | `API_REFLECTED` atau `API_RISK` | API/JSON/download response merefleksikan payload. Perlu konfirmasi frontend/browser sink sebelum disebut valid. |
| `[RISK]` | `REFLECTED_RISK` | Refleksi kuat dan berisiko tinggi, tetapi belum terbukti eksekusi. |
| `[LOW]` | `REFLECTED_LOW` | Ada refleksi, tetapi konteksnya lebih lemah. |
| `[NO]` | `NOT_CONFIRMED` | Tidak ada bukti refleksi/eksekusi yang cukup. |
| `[SKIP]` | `NETWORK_ERROR` atau `HTTP_SKIPPED` | Target gagal dijangkau atau status tertentu dilewati setelah threshold. |

Prinsip akurasi:

- `[VALID]` hanya untuk bukti eksekusi yang terkonfirmasi.
- Response API yang hanya memantulkan payload tidak otomatis dianggap valid.
- `[API]` tetap penting karena sering menjadi sumber XSS saat data API dimasukkan lagi ke frontend tanpa encoding.
- Kalau `[API]` muncul, XSSentinel menampilkan URL lengkap dengan payload agar bisa diuji ulang manual di browser, proxy, atau frontend sink.

## Output Penting

Contoh hasil `[API]`:

```text
[API  ] #0008 agent=01/01 GET HTTP=200 API_REFLECTED API response reflects payload; browser confirmation required eviden...
  url: https://target.test/api/search?q=%3Csvg%20onload%3Dalert%281%29%3E
  payload: <svg onload=alert(1)>
```

Contoh ringkasan ketika belum ada eksekusi valid:

```text
[DONE] no confirmed execution
  stats: confirmed=0 api=1 risk=0 low=0 no=7 skipped=0
  api: API_REFLECTED
  evidence: application/json reflects payload; browser=no alert/confirm/prompt popup detected
  payload: <svg onload=alert(1)>
  url: https://target.test/api/search?q=%3Csvg%20onload%3Dalert%281%29%3E
```

Contoh hasil valid:

```text
[VALID] #0001 GET HTTP=200 CONFIRMED payload="\"><svg/onload=prompt(1)>" evidence="prompt:1"

[FOUND] confirmed XSS
  method: GET    http: 200    tested: 4
  stats: confirmed=1 api=0 risk=1 low=1 no=1 skipped=0
  payload: "><svg/onload=prompt(1)>
  browser: prompt:1
  url: https://target.test/search?q=%22%3E%3Csvg/onload%3Dprompt(1)%3E
```

## Scan Flow

1. Target dinormalisasi dan divalidasi harus `http://` atau `https://`.
2. Query parameter dari URL dibuat menjadi fuzz target.
3. Jika URL awal tidak punya parameter, XSSentinel mencoba discovery dari form, link, input, dan JavaScript same-origin.
4. Payload dimuat dari file payload utama.
5. Smart mode memilih payload prioritas dulu.
6. Tool melakukan context probing untuk memahami posisi refleksi.
7. Request payload dikirim ke target.
8. Response dianalisis untuk refleksi, API evidence, download evidence, dan konteks DOM.
9. Jika browser tersedia, payload yang layak akan diverifikasi dengan Chromium/Playwright.
10. Jika tidak ada valid di batch awal, scanner lanjut ke fallback payload yang lebih luas.

## Discovery Target

Jika target awal tidak punya query parameter, XSSentinel mencoba menemukan input dari halaman:

- GET form.
- POST form.
- Link same-origin dengan query string.
- Standalone input field.
- Nama parameter dari JavaScript same-origin.

Saat banyak endpoint ditemukan, scanner memakai worker pool. Output seperti ini berarti worker sedang bekerja:

```text
[START] workers=4 targets=12 parallel=on
[START] scanning | active=4/12 done=0/12 phases=analysis:4
[START] agent=01/04 state=assigned source=form method=POST param=q
```

## API Testing

XSS di API biasanya tidak selalu langsung muncul popup, karena API hanya mengembalikan data. XSS baru valid kalau data API itu masuk ke frontend dan dieksekusi di sink berbahaya seperti `innerHTML`, `document.write`, template HTML tanpa escaping, atau render SVG/HTML aktif.

Untuk API, hasil yang bagus dibaca seperti ini:

- `[API]` berarti payload sampai dan terefleksi di API.
- URL lengkap yang dicetak bisa dipakai untuk retest manual.
- Cek frontend mana yang memakai API tersebut.
- Jika frontend memasukkan response API ke HTML tanpa encoding dan payload berjalan, barulah itu valid XSS.

Contoh endpoint API:

```bash
xssentinel "https://target.test/api/search?q=test"
```

Jika menemukan `[API]`, lanjutkan verifikasi manual:

- Buka URL hasil yang dicetak.
- Cek response body dan content type.
- Cari halaman frontend yang menggunakan endpoint itu.
- Uji apakah response API masuk ke DOM sebagai HTML aktif atau hanya sebagai text aman.

## Browser Validation

XSSentinel memakai Chromium lokal atau Playwright jika tersedia. Browser validation mencoba membuka URL payload dan mendeteksi `alert`, `confirm`, atau `prompt`.

Install Chromium di Debian/Ubuntu:

```bash
sudo apt install chromium
```

Alternatif Playwright:

```bash
python3 -m pip install playwright
python3 -m playwright install chromium
```

Jika browser tidak tersedia, scanner tetap berjalan, tetapi hasil validasi akan terbatas pada HTTP/reflection/API evidence. Dalam kondisi ini, `[VALID]` bisa lebih jarang muncul karena tidak ada bukti eksekusi browser.

## HTTP Skip Behavior

XSSentinel hanya menganggap status berikut sebagai kandidat skip otomatis:

- `204 No Content`
- `304 Not Modified`

Tool tidak langsung skip pada satu response. Skip baru terjadi setelah status kandidat yang sama muncul berulang kali tanpa refleksi.

Status seperti `400`, `401`, `403`, `404`, `405`, `406`, `410`, `413`, `415`, `429`, dan `5xx` tetap dianalisis normal. Jika payload terefleksi, hasil tetap bisa menjadi `[LOW]`, `[RISK]`, `[API]`, atau `[VALID]` sesuai evidence.

## File Payload

File utama payload:

```text
xss-payloads.txt
```

File pendukung/eksperimen:

```text
smart-selected-180-payloads.txt
```

Catatan:

- Baris kosong dan komentar diabaikan.
- Smart mode melakukan perluasan payload seperti variasi encoding, escaping, dan mutasi sintaks.
- `selected=90` di output berarti 90 payload prioritas diuji dulu, bukan berarti total payload hanya 90.

## Troubleshooting

### `xssentinel: command not found`

Tambahkan `~/.local/bin` ke `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Lalu cek:

```bash
xssentinel -h
```

### Sudah edit source tapi command belum berubah

Jalankan:

```bash
xssentinel -restart
```

Ini memasang ulang runtime dari source lokal yang tersimpan.

### Ingin memperbarui tool

Jalankan:

```bash
xssentinel -update
```

Command ini mengambil versi terbaru dan memasang ulang runtime XSSentinel.

### `[API]` muncul tapi tidak ada popup

Itu normal. `[API]` berarti payload terefleksi di response API/download, bukan bukti eksekusi browser. Gunakan URL yang dicetak untuk mencari frontend sink yang memakai response API tersebut.

### Banyak `[RISK]` atau `[LOW]`, tapi tidak ada `[VALID]`

Artinya payload terefleksi, tetapi belum ada bukti eksekusi. Kemungkinan penyebab:

- Browser validation tidak tersedia.
- Payload masuk sebagai text aman, bukan HTML aktif.
- CSP atau sanitasi frontend mencegah eksekusi.
- Endpoint hanya API dan tidak langsung render HTML.

### Browser validation tidak aktif

Cek output `chromium=on/off`. Jika `off`, install Chromium atau Playwright seperti bagian Browser Validation.

### Target sering error `500` atau response aneh

Coba mode default tanpa `--all-params`, karena satu parameter per request biasanya lebih stabil. Gunakan `--all-params` hanya jika endpoint memang butuh beberapa parameter berubah bersamaan.

### Scan terasa lama

Hal ini bisa terjadi jika banyak endpoint ditemukan atau payload fallback sudah berjalan. Perhatikan output worker seperti `active`, `done`, dan `phases` untuk melihat progress.

## Project Layout

```text
.
|-- main.py
|-- install.sh
|-- uninstall.sh
|-- xss-payloads.txt
|-- smart-selected-180-payloads.txt
|-- useragents.txt
`-- xssentinel_core/
```

Installer menyalin runtime ke:

```text
~/.local/share/xssentinel
```

Wrapper command dibuat di:

```text
~/.local/bin/xssentinel
```

## Uninstall

```bash
./uninstall.sh
```

## License

XSSentinel dirilis dengan lisensi Apache License 2.0. Lihat [LICENSE](LICENSE) untuk teks lisensi lengkap.

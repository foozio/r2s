Sudah kubuat sebuah **tool pendeteksi defensif** untuk CVE-2025-55182 (React2Shell) dan menyimpannya sebagai `/mnt/data/detect_react2shell.py`.

Ringkasan singkat:

* Tool ini **hanya mendeteksi** (lokal + pasif pada URL) — **tidak** berisi kode eksploit atau langkah pemanfaatan.
* Ia memeriksa `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, serta `node_modules` untuk paket:

  * `react-server-dom-webpack`, `react-server-dom-parcel`, `react-server-dom-turbopack`
  * dan juga memperingatkan bila `react` major version 19 terdeteksi.
* Dapat melakukan *passive* HTTP check pada sebuah URL (butuh `requests`).
* Memberikan rekomendasi patching dan mitigasi singkat.

Download / jalankan:

* [Download script](/mnt/data/detect_react2shell.py) — atau jalankan langsung di lingkunganmu:

  * `python /mnt/data/detect_react2shell.py --path /path/to/your/project`
  * `python /mnt/data/detect_react2shell.py --url https://your-site.example`

Catatan penting:

* Pastikan menjalankan upgrade ke versi patched jika tool memberi peringatan:

  * patched versions: `19.0.1`, `19.1.2`, `19.2.1` (untuk paket react-server-dom-*)
* Jika ingin, aku bisa:

  * Jalankan pemeriksaan cepat pada repo yang kamu upload atau path yang kamu arahkan (kamu bisa upload zip), atau
  * Modifikasi tool supaya memeriksa range versi (>= / <) atau mengintegrasikannya ke CI (GitHub Actions / GitLab CI).
    Mau aku tambahkan pengecekan ke CI atau buat versi yang scan banyak repositori sekaligus?

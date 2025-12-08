# React2Shell Vulnerability Checker

**CVE-2025-55182 Detection Tool for Ubuntu Linux and Windows 10/11**

## Deskripsi

Alat ini mendeteksi potensi kerentanan React2Shell (CVE-2025-55182) dalam proyek React dengan memeriksa:
- File `package.json` dan file lock untuk paket rentan
- Direktori `node_modules` untuk dependensi yang terpengaruh
- URL secara pasif untuk deteksi jarak jauh

> **Catatan Penting:** Alat ini hanya untuk deteksi (lokal dan pasif pada URL) — **tidak** berisi kode eksploitasi atau langkah-langkah pemanfaatan kerentanan.

## Paket yang Diperiksa

Alat ini akan memeriksa keberadaan paket-paket berikut:
- `react-server-dom-webpack`
- `react-server-dom-parcel`
- `react-server-dom-turbopack`
- `react` (versi 19.x.x - karena potensi keterlibatan dalam kerentanan)

## Versi Tertambal

Jika ditemukan kerentanan, pastikan untuk mengupgrade ke versi tertambal berikut:
- `react-server-dom-webpack`, `react-server-dom-parcel`, `react-server-dom-turbopack`: versi 19.0.1, 19.1.2, atau 19.2.1

## Instalasi

### Ubuntu Linux
```bash
# Buat lingkungan virtual (opsional tapi direkomendasikan)
python3 -m venv venv
source venv/bin/activate  # Aktifkan lingkungan virtual

# Instal dependensi
pip install -r requirements.txt

# Atau gunakan skrip instalasi
chmod +x install_linux.sh
./install_linux.sh
```

### Windows 10/11
```cmd
# Buka Command Prompt sebagai Administrator
# Instal dependensi
pip install -r requirements.txt

# Atau gunakan skrip instalasi
install_windows.bat
```

### Instalasi Cross-Platform
```bash
# Untuk Ubuntu Linux
python3 install_cross_platform.py

# Untuk Windows 10/11
python install_cross_platform.py
```

## Penggunaan

### Pemeriksaan Lokal
```bash
# Memindai proyek lokal
python3 react2shell_checker.py --path /path/to/your/project

# Pada Windows
python react2shell_checker.py --path C:\path\to\your\project
```

### Pemeriksaan URL
```bash
# Memeriksa URL secara pasif
python3 react2shell_checker.py --url https://your-site.example

# Pada Windows
python react2shell_checker.py --url https://your-site.example
```

## Contoh Output

### Jika Aman
```
[INFO] Scanning path: /path/to/your/project
[INFO] Found package.json: /path/to/your/project/package.json
[SAFE] No vulnerabilities detected!
```

### Jika Ditemukan Kerentanan
```
[INFO] Scanning path: /path/to/your/project
[INFO] Found package.json: /path/to/your/project/package.json
[WARNING] Found potential vulnerabilities:
  - react-server-dom-webpack@19.0.0
  - react@19.1.0

[RECOMMENDATION] If any vulnerabilities are found, upgrade to patched versions:
  - For react-server-dom-* packages: 19.0.1, 19.1.2, or 19.2.1
  - For react: Upgrade to a patched version >= 19.x.x if needed
```

## Fitur Tambahan

- Mendeteksi berbagai format file lock (package-lock.json, yarn.lock, pnpm-lock.yaml)
- Mencari secara rekursif file `package.json` dalam subdirektori
- Pemeriksaan pasif terhadap URL untuk mendeteksi aplikasi React
- Dukungan untuk berbagai notasi versi (^, ~, >=, <=)
- Antarmuka baris perintah yang intuitif

## Persyaratan Sistem

- Python 3.6 atau lebih tinggi
- Modul Python: `requests`, `packaging`
- Akses baca ke file proyek (package.json, node_modules, dll.)

## Lisensi

Alat ini disediakan sebagai alat deteksi keamanan untuk membantu pengembang mengidentifikasi dan memperbaiki kerentanan di proyek mereka. Gunakan secara bertanggung jawab sesuai dengan kebijakan keamanan organisasi Anda.
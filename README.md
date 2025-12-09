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

### Persyaratan Sistem

- Python 3.6 atau lebih tinggi
- pip (Python package installer)
- Git (untuk cloning repository)

### Instalasi Cepat (Cross-Platform)

```bash
# Clone repository
git clone https://github.com/foozio/r2s.git
cd react2shell-checker

# Buat virtual environment (direkomendasikan)
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# atau
venv\Scripts\activate     # Windows

# Instal dependensi
pip install -r requirements.txt

# Untuk development/testing
pip install -r requirements-dev.txt
```

### Instalasi Platform-Specific

```bash
# Ubuntu Linux
chmod +x install_linux.sh
./install_linux.sh

# Windows
install_windows.bat

# Cross-platform installer
python3 install_cross_platform.py
```

## Penggunaan

### Pemeriksaan Lokal

```bash
# Menggunakan script unified (cross-platform)
python3 react2shell_checker_unified.py --path /path/to/your/project

# Atau menggunakan script platform-specific
python3 react2shell_checker_linux.py --path /path/to/your/project  # Linux
python react2shell_checker_windows.py --path C:\path\to\your\project  # Windows
```

### Pemeriksaan URL

```bash
# Pemeriksaan pasif dengan validasi keamanan
python3 react2shell_checker_unified.py --url https://your-site.example
```

### Opsi Tambahan

```bash
# Menjalankan dengan verbose output
python3 react2shell_checker_unified.py --path /project --verbose --log-file scan.log

# Menggunakan file konfigurasi kustom
python3 react2shell_checker_unified.py --path /project --config custom-config.yaml

# Menjalankan tests
pytest tests/

# Menjalankan dengan coverage
pytest --cov=react2shell_checker_unified tests/
```

### Konfigurasi

Tool ini mendukung file konfigurasi YAML untuk menyesuaikan aturan deteksi kerentanan:

```yaml
# react2shell.yaml
vulnerable_packages:
  react-server-dom-webpack:
    - "<19.0.1"
  custom-package:
    - ">=1.0.0 <1.2.0"

scan:
  max_workers: 8
  exclude_dirs:
    - node_modules
    - .git
```

Jalankan dengan konfigurasi kustom:

```bash
python3 react2shell_checker_unified.py --path /project --config react2shell.yaml
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

## Fitur Utama

- **Deteksi Multi-Format**: Mendukung package.json, package-lock.json, yarn.lock, pnpm-lock.yaml
- **Pemindaian Rekursif**: Otomatis memindai subdirektori untuk file package.json tambahan
- **Validasi URL Aman**: Pemeriksaan pasif dengan proteksi SSRF (Server-Side Request Forgery)
- **Validasi Path Aman**: Proteksi terhadap directory traversal attacks
- **Dukungan Versi Fleksibel**: Menangani berbagai notasi versi (^, ~, >=, <=)
- **Cross-Platform**: Berjalan di Linux, Windows, dan macOS
- **Testing Lengkap**: Unit tests, integration tests, dan performance tests
- **Output Terstruktur**: Format output yang konsisten dan mudah diparsing

## Persyaratan Sistem

- Python 3.6 atau lebih tinggi
- Modul Python: `requests`, `packaging`
- Untuk development: `pytest`, `pytest-mock`
- Akses baca ke file proyek (package.json, node_modules, dll.)

## Keamanan

Tool ini mengimplementasikan beberapa lapisan keamanan:

- **Validasi URL**: Mencegah akses ke localhost dan IP private
- **Validasi Path**: Deteksi dan pencegahan directory traversal
- **Input Sanitization**: Validasi semua input user
- **Safe File Operations**: Read-only access dengan error handling

## Testing

```bash
# Jalankan semua tests
pytest

# Jalankan dengan coverage
pytest --cov=react2shell_checker_unified

# Jalankan specific test file
pytest tests/test_checker.py

# Jalankan performance tests
pytest tests/test_performance.py -m slow
```

## Development

### Struktur Kode

```
react2shell-checker/
├── react2shell_checker_unified.py    # Main cross-platform script
├── react2shell_checker_linux.py      # Linux-specific (legacy)
├── react2shell_checker_windows.py    # Windows-specific (legacy)
├── install_*.py/sh/bat               # Installation scripts
├── tests/                            # Test suite
│   ├── test_checker.py              # Unit tests
│   ├── test_integration.py          # Integration tests
│   └── test_performance.py          # Performance tests
├── requirements.txt                  # Runtime dependencies
├── requirements-dev.txt             # Development dependencies
└── README.md                        # This file
```

### Contributing

1. Fork repository
2. Buat feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push ke branch (`git push origin feature/amazing-feature`)
5. Buat Pull Request

### Code Quality

- Jalankan tests sebelum commit: `pytest`
- Format code dengan Black: `black .`
- Lint dengan Flake8: `flake8`
- Type checking dengan MyPy: `mypy react2shell_checker_unified.py`

## Changelog

### v2.0.0 (Latest)

- ✅ Unified cross-platform script
- ✅ Enhanced security validations
- ✅ Comprehensive test suite
- ✅ Improved error handling
- ✅ Performance optimizations

### v1.0.0

- ✅ Basic vulnerability detection
- ✅ Platform-specific scripts
- ✅ URL passive checking
- ✅ Multiple lock file support

## Lisensi

Alat ini disediakan sebagai alat deteksi keamanan untuk membantu pengembang mengidentifikasi dan memperbaiki kerentanan di proyek mereka. Gunakan secara bertanggung jawab sesuai dengan kebijakan keamanan organisasi Anda.

## Support

- **Issues**: [GitHub Issues](https://github.com/foozio/r2s/issues)
- **Discussions**: [GitHub Discussions](https://github.com/foozio/r2s/discussions)
- **Security**: Untuk laporan keamanan, email ke security@your-org.com

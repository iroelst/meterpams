# MeterPAMS — paket pengujian menu dasar

Paket ini ditujukan untuk menguji **Profil Perusahaan, Area, Golongan Pelanggan, dan tambah pelanggan dengan ID otomatis** melalui Cloudflare Worker dan database Neon yang sudah digunakan proyek.

## Isi paket
- `public/index.html` — antarmuka aplikasi
- `worker.js` — API yang menggunakan `DATABASE_URL`, `APP_USERS`, dan `JWT_SECRET` di Cloudflare Workers Secrets
- `wrangler.jsonc` dan `package.json` — konfigurasi deploy proyek

## Deploy
1. Simpan salinan proyek dan jangan hapus secrets yang sudah ada.
2. Ganti `public/index.html` dan `worker.js` di proyek GitHub dengan file dari paket.
3. Pastikan `wrangler.jsonc` tetap memakai `public` sebagai folder assets dan `run_worker_first` untuk `/api/*`.
4. Deploy dari folder proyek menggunakan `npx wrangler deploy`.
5. Buka URL Worker, login, lalu uji menu dasar.

## Urutan pengujian
1. Buka **Pengaturan & Backup → Ubah Pengaturan**, simpan nama Perusahaan, denda bulanan, dan tanggal jatuh tempo.
2. Buka **Area**, tambah satu area dan pastikan muncul pada daftar.
3. Buka **Jenis Pelanggan** (ditampilkan sebagai Golongan Pelanggan), tambah satu golongan aktif dan pastikan muncul pada daftar.
4. Buka **Pelanggan → Pelanggan**, pastikan ID Pelanggan terisi otomatis dan dropdown Area/Golongan memuat data yang baru dibuat.
5. Simpan pelanggan, lalu pastikan ID yang sama muncul di daftar pelanggan.

## Batas pengujian
- Menu Catat Meter, Tagihan, Pembayaran, Laporan, Backup, dan alur transaksi penuh **belum dianggap lulus uji**.
- Kode dapat diperiksa secara sintaks, tetapi simpan/baca database produksi tetap harus diuji setelah deploy di akun Cloudflare/Neon Anda.
- Jangan gunakan data pelanggan asli untuk pengujian awal; gunakan data percobaan.

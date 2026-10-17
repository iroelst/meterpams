# Meter Pams — backend Cloudflare Worker + Neon

Paket ini adalah backend awal yang dapat membaca/menulis tabel yang sudah ada pada database Neon. HTML saat ini masih perlu diintegrasikan dengan endpoint API sebelum tombol-tombol UI menyimpan data.

## File
- `worker.js`: API backend, login berbasis secret, role admin/staff, akses tabel allowlist.
- `wrangler.jsonc`: konfigurasi Worker dan aset statis.
- `package.json`: dependensi.
- `index.html`: salinan HTML rancangan saat ini.

## Penting
- Tidak ada data contoh produksi.
- Jangan commit `DATABASE_URL`, `JWT_SECRET`, atau `APP_USERS`.
- Endpoint API belum menggantikan audit keamanan dan pengujian transaksi sebelum dipakai untuk data pelanggan nyata.
- Role staff hanya dapat menulis `meter_readings` dan `payments`; role admin dapat mengelola tabel.
- `GET /api/health` hanya menguji koneksi DB dan tidak memerlukan login.
- Karena `assets.directory` adalah folder root untuk mempermudah deploy GitHub saat ini, pastikan tidak menyimpan file rahasia di repository.

## Secrets di Cloudflare
Buka Worker `meterpams` → Settings → Variables and Secrets → Add secret:
1. `DATABASE_URL`: connection string Neon lengkap (gunakan password database; jangan kirim ke chat).
2. `JWT_SECRET`: string acak panjang minimal 32 karakter.
3. `APP_USERS`: JSON satu baris, contoh struktur (GANTI username/password dengan kredensial kuat, jangan gunakan contoh ini):
   `[{"username":"admin","password":"GANTI_DENGAN_PASSWORD_KUAT","role":"admin"},{"username":"petugas","password":"GANTI_DENGAN_PASSWORD_KUAT","role":"staff"}]`
Simpan semua sebagai Secret, bukan Plaintext variable. Password pada APP_USERS adalah password aplikasi; gunakan kredensial unik dan kuat. Untuk sistem produksi, sebaiknya ganti dengan autentikasi yang menyimpan hash password dan prosedur reset.

## GitHub
Unggah `worker.js`, `wrangler.jsonc`, `package.json`, dan file ini ke root repository bersama `index.html`. Commit perubahan. Cloudflare Pages/Workers build:
- Build command: `npm install`
- Deploy command: `npx wrangler deploy`
- Root directory: `/` atau kosong.

## Pengujian
Setelah deploy, buka `https://meterpams.<subdomain>.workers.dev/api/health`. Jika sukses, respons berisi `ok:true` dan nama database. Jika gagal, periksa secret `DATABASE_URL` dan status compute Neon.
Login dilakukan dengan POST JSON ke `/api/login`, lalu sertakan token sebagai `Authorization: Bearer <token>` untuk endpoint `/api/<nama_tabel>`.

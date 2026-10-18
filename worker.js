import { neon } from "@neondatabase/serverless";

const TABLES = {
  app_settings: ["id","business_name","monthly_penalty","due_day","created_at"],
  areas: ["id","name","description","created_at"],
  customer_types: ["id","name","description","is_active","created_at"],
  customers: ["id","customer_no","name","address","phone","area_id","customer_type_id","status","created_at"],
  meters: ["id","meter_no","customer_id","initial_reading","installed_at","removed_at","status","created_at"],
  meter_readings: ["id","meter_id","period","previous_reading","current_reading","usage_m3","recorded_by","notes","created_at"],
  meter_replacements: ["id","customer_id","old_meter_id","new_meter_id","old_final_reading","new_initial_reading","replacement_date","notes","created_at"],
  tariff_brackets: ["id","customer_type_id","min_usage","max_usage","rate_per_m3","created_at"],
  bills: ["id","bill_no","customer_id","meter_reading_id","period","usage_m3","water_charge","admin_fee","penalty","total_amount","paid_amount","due_date","status","created_at"],
  payments: ["id","bill_id","payment_date","amount","method","reference_no","received_by","notes","created_at"]
};

const READ_ONLY = new Set(["id", "created_at", "usage_m3"]);

const STAFF_READ = new Set([
  "areas", "customer_types", "customers", "meters",
  "meter_readings", "bills", "payments", "app_settings",
  "tariff_brackets", "meter_replacements"
]);

const STAFF_WRITE = new Set(["meter_readings", "payments"]);

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Content-Type": "application/json; charset=utf-8"
};

const response = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: cors });

const b64 = (bytes) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

const enc = new TextEncoder();

async function sign(payload, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const body = b64(enc.encode(JSON.stringify(payload)));
  const sig = b64(
    await crypto.subtle.sign("HMAC", key, enc.encode(body))
  );

  return `${body}.${sig}`;
}

async function verify(token, secret) {
  try {
    if (!secret || typeof token !== "string") return null;

    const [body, sig] = token.split(".");
    if (!body || !sig) return null;

    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const expected = b64(
      await crypto.subtle.sign("HMAC", key, enc.encode(body))
    );

    if (sig !== expected) return null;

    const normalized = body
      .replace(/-/g, "+")
      .replace(/_/g, "/");

    const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
    const payload = JSON.parse(atob(padded));

    if (!payload.exp || payload.exp < Date.now() / 1000) return null;

    return payload;
  } catch {
    return null;
  }
}

function safeEqual(a, b) {
  if (
    typeof a !== "string" ||
    typeof b !== "string" ||
    a.length !== b.length
  ) return false;

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

async function userFromRequest(request, env) {
  const header = request.headers.get("Authorization") || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  return verify(token, env.JWT_SECRET);
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    const url = new URL(request.url);

    // =====================================================
    // HEALTH CHECK: MEMERIKSA KONEKSI NEON
    // =====================================================
    if (
      url.pathname === "/api/health" &&
      request.method === "GET"
    ) {
      try {
        if (!env.DATABASE_URL) {
          return response({
            ok: false,
            error: "Secret DATABASE_URL tidak terbaca oleh Worker."
          }, 503);
        }

        const sql = neon(env.DATABASE_URL);

        const rows = await sql`
          SELECT current_database() AS database,
                 now() AS server_time
        `;

        return response({
          ok: true,
          database: rows[0].database,
          server_time: rows[0].server_time
        });
      } catch (e) {
        console.error("MeterPAMS database health error:", e);

        return response({
          ok: false,
          error: "Koneksi database gagal.",
          detail: String(e?.message || e).slice(0, 300)
        }, 503);
      }
    }

    // =====================================================
    // LOGIN
    // =====================================================
    if (
      url.pathname === "/api/login" &&
      request.method === "POST"
    ) {
      if (!env.APP_USERS || !env.JWT_SECRET) {
        return response({
          error: "Authentication secrets are not configured."
        }, 503);
      }

      let body;

      try {
        body = await request.json();
      } catch {
        return response({ error: "Invalid JSON" }, 400);
      }

      let users;

      try {
        users = JSON.parse(env.APP_USERS);

        if (!Array.isArray(users)) {
          throw new Error("APP_USERS harus berupa array.");
        }
      } catch {
        return response({
          error: "APP_USERS secret must be a valid JSON array."
        }, 500);
      }

      const username = body?.username;
      const password = body?.password;

      const user = users.find(
        item =>
          safeEqual(item?.username, username) &&
          safeEqual(item?.password, password)
      );

      if (!user || !["admin", "staff"].includes(user.role)) {
        return response({
          error: "Username atau password salah."
        }, 401);
      }

      const token = await sign({
        sub: user.username,
        role: user.role,
        exp: Math.floor(Date.now() / 1000) + 60 * 60 * 8
      }, env.JWT_SECRET);

      return response({
        token,
        username: user.username,
        role: user.role,
        expires_in: 28800
      });
    }

    // =====================================================
    // STATIC ASSETS
    // =====================================================
    if (!url.pathname.startsWith("/api/")) {
      if (env.ASSETS) {
        return env.ASSETS.fetch(request);
      }

      return response({
        error: "Static asset binding ASSETS belum dikonfigurasi."
      }, 404);
    }

    // =====================================================
    // AUTHENTICATION UNTUK API
    // =====================================================
    const user = await userFromRequest(request, env);

    if (!user) {
      return response({
        error: "Silakan login terlebih dahulu."
      }, 401);
    }

    const parts = url.pathname.split("/").filter(Boolean);

    if (
      parts.length !== 2 ||
      parts[0] !== "api" ||
      !Object.hasOwn(TABLES, parts[1])
    ) {
      return response({
        error: "Endpoint tidak ditemukan."
      }, 404);
    }

    const table = parts[1];
    const cols = TABLES[table];
    const isAdmin = user.role === "admin";

    // =====================================================
    // GET DATA
    // =====================================================
    if (request.method === "GET") {
      if (!isAdmin && !STAFF_READ.has(table)) {
        return response({ error: "Akses ditolak." }, 403);
      }

      try {
        if (!env.DATABASE_URL) {
          throw new Error("DATABASE_URL tidak tersedia.");
        }

        const sql = neon(env.DATABASE_URL);

        const requestedLimit = Number(
          url.searchParams.get("limit") || 100
        );

        const limit = Math.min(
          Math.max(
            Number.isFinite(requestedLimit) ? requestedLimit : 100,
            1
          ),
          500
        );

        const rows = await sql.query(
          `SELECT ${cols.map(c => `"${c}"`).join(", ")}
           FROM "${table}"
           ORDER BY "id" DESC
           LIMIT $1`,
          [limit]
        );

        return response({ data: rows });
      } catch (e) {
        console.error(`MeterPAMS GET ${table} error:`, e);

        return response({
          error: "Gagal membaca data database."
        }, 500);
      }
    }

    // =====================================================
    // INSERT DATA
    // =====================================================
    if (request.method === "POST") {
      if (!isAdmin && !STAFF_WRITE.has(table)) {
        return response({ error: "Akses tulis ditolak." }, 403);
      }

      let body;

      try {
        body = await request.json();
      } catch {
        return response({ error: "Invalid JSON" }, 400);
      }

      if (
        !body ||
        Array.isArray(body) ||
        typeof body !== "object"
      ) {
        return response({
          error: "Body harus berupa objek JSON."
        }, 400);
      }

      // ID pelanggan dibuat oleh server; pengguna tidak dapat menentukan ID sendiri.
      if (table === "customers") {
        const random = new Uint8Array(4);
        crypto.getRandomValues(random);
        const suffix = Array.from(random, byte => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
        const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
        body.customer_no = `PEL-${date}-${suffix}`;
      }

      const keys = Object.keys(body).filter(
        key => cols.includes(key) && !READ_ONLY.has(key)
      );

      if (!keys.length) {
        return response({
          error: "Tidak ada kolom yang bisa disimpan."
        }, 400);
      }

      if (
        table === "meter_readings" &&
        Number(body.current_reading) < Number(body.previous_reading)
      ) {
        return response({
          error: "Angka meter sekarang tidak boleh lebih kecil dari angka sebelumnya."
        }, 400);
      }

      if (
        table === "payments" &&
        !(Number(body.amount) > 0)
      ) {
        return response({
          error: "Nominal pembayaran harus lebih dari nol."
        }, 400);
      }

      try {
        if (!env.DATABASE_URL) {
          throw new Error("DATABASE_URL tidak tersedia.");
        }

        const sql = neon(env.DATABASE_URL);
        const values = keys.map(key => body[key]);

        const query = `
          INSERT INTO "${table}"
          (${keys.map(key => `"${key}"`).join(",")})
          VALUES (${keys.map((_, i) => `$${i + 1}`).join(",")})
          RETURNING ${cols.map(c => `"${c}"`).join(",")}
        `;

        const rows = await sql.query(query, values);

        return response({ data: rows[0] }, 201);
      } catch (e) {
        console.error(`MeterPAMS POST ${table} error:`, e);

        return response({
          error: "Gagal menyimpan data. Periksa relasi wajib dan format kolom."
        }, 400);
      }
    }

    // =====================================================
    // UPDATE DAN DELETE: KHUSUS ADMIN
    // =====================================================
    if (
      request.method === "PATCH" ||
      request.method === "DELETE"
    ) {
      if (!isAdmin) {
        return response({
          error: "Hanya admin yang boleh mengubah atau menghapus data."
        }, 403);
      }

      const id = url.searchParams.get("id");

      if (!id || !/^\d+$/.test(id)) {
        return response({ error: "ID tidak valid." }, 400);
      }

      try {
        if (!env.DATABASE_URL) {
          throw new Error("DATABASE_URL tidak tersedia.");
        }

        const sql = neon(env.DATABASE_URL);

        if (request.method === "DELETE") {
          const rows = await sql.query(
            `DELETE FROM "${table}" WHERE id=$1 RETURNING id`,
            [Number(id)]
          );

          return rows.length
            ? response({ deleted: true })
            : response({ error: "Data tidak ditemukan." }, 404);
        }

        let body;

        try {
          body = await request.json();
        } catch {
          return response({ error: "Invalid JSON" }, 400);
        }

        if (
          !body ||
          Array.isArray(body) ||
          typeof body !== "object"
        ) {
          return response({
            error: "Body harus berupa objek JSON."
          }, 400);
        }

        const keys = Object.keys(body).filter(
          key => cols.includes(key) && !READ_ONLY.has(key)
        );

        if (!keys.length) {
          return response({
            error: "Tidak ada kolom yang bisa diubah."
          }, 400);
        }

        const values = keys.map(key => body[key]);
        values.push(Number(id));

        const rows = await sql.query(
          `UPDATE "${table}"
           SET ${keys.map((key, i) => `"${key}"=$${i + 1}`).join(",")}
           WHERE id=$${values.length}
           RETURNING ${cols.map(c => `"${c}"`).join(",")}`,
          values
        );

        return rows.length
          ? response({ data: rows[0] })
          : response({ error: "Data tidak ditemukan." }, 404);
      } catch (e) {
        console.error(`MeterPAMS ${request.method} ${table} error:`, e);

        return response({
          error: "Perubahan gagal. Periksa relasi dan aturan database."
        }, 400);
      }
    }

    return response({ error: "Method tidak didukung." }, 405);
  }
};
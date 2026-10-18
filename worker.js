import { neon } from "@neondatabase/serverless";

const TABLES = {
  app_settings: ["id","business_name","monthly_penalty","due_day","created_at","organization_id"],
  areas: ["id","name","description","created_at","organization_id"],
  customer_types: ["id","name","description","is_active","created_at","organization_id"],
  customers: ["id","customer_no","name","address","phone","area_id","customer_type_id","status","created_at","organization_id"],
  meters: ["id","meter_no","customer_id","initial_reading","installed_at","removed_at","status","created_at","organization_id"],
  meter_readings: ["id","meter_id","period","previous_reading","current_reading","usage_m3","recorded_by","notes","created_at","organization_id"],
  meter_replacements: ["id","customer_id","old_meter_id","new_meter_id","old_final_reading","new_initial_reading","replacement_date","notes","created_at","organization_id"],
  tariff_brackets: ["id","customer_type_id","min_usage","max_usage","rate_per_m3","created_at","organization_id"],
  bills: ["id","bill_no","customer_id","meter_reading_id","period","usage_m3","water_charge","admin_fee","penalty","total_amount","paid_amount","due_date","status","created_at","organization_id"],
  payments: ["id","bill_id","payment_date","amount","method","reference_no","received_by","notes","created_at","organization_id"]
};
const TENANT_TABLES = Object.keys(TABLES);
const READ_ONLY = new Set(["id", "created_at", "usage_m3", "organization_id"]);
const STAFF_READ = new Set(TENANT_TABLES);
const STAFF_WRITE = new Set(["meter_readings", "payments"]);
const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Content-Type": "application/json; charset=utf-8"
};
const response = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: cors });
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
const enc = new TextEncoder();
async function sign(payload, secret) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const body = b64(enc.encode(JSON.stringify(payload)));
  const sig = b64(await crypto.subtle.sign("HMAC", key, enc.encode(body)));
  return `${body}.${sig}`;
}
async function verify(token, secret) {
  try {
    if (!secret || typeof token !== "string") return null;
    const [body, sig] = token.split("."); if (!body || !sig) return null;
    const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const expected = b64(await crypto.subtle.sign("HMAC", key, enc.encode(body)));
    if (sig !== expected) return null;
    const normalized = body.replace(/-/g, "+").replace(/_/g, "/");
    const payload = JSON.parse(atob(normalized + "=".repeat((4-normalized.length%4)%4)));
    if (!payload.exp || payload.exp < Date.now()/1000) return null;
    return payload;
  } catch { return null; }
}
function safeEqual(a,b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let result=0; for(let i=0;i<a.length;i++) result |= a.charCodeAt(i)^b.charCodeAt(i); return result===0;
}
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 210000, hash: "SHA-256" }, key, 256);
  return `pbkdf2$210000$${b64(salt)}$${b64(bits)}`;
}
async function verifyPassword(password, stored) {
  // Stored format: pbkdf2$iterations$saltBase64Url$hashBase64Url
  try {
    const [scheme, iterText, saltText, hashText] = String(stored).split("$");
    const iterations = Number(iterText);
    if (scheme !== "pbkdf2" || !Number.isInteger(iterations) || iterations < 100000 || !saltText || !hashText) return false;
    const decode = t => Uint8Array.from(atob(t.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-t.length%4)%4)), c=>c.charCodeAt(0));
    const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({name:"PBKDF2", salt:decode(saltText), iterations, hash:"SHA-256"}, key, 256);
    return safeEqual(b64(bits), hashText);
  } catch { return false; }
}
async function userFromRequest(request, env) {
  const h=request.headers.get("Authorization")||"";
  return verify(h.startsWith("Bearer ")?h.slice(7):"", env.JWT_SECRET);
}
function jsonBody(request) { return request.json().catch(()=>null); }
function isOwner(user) { return user?.role === "owner"; }
function isAdmin(user) { return user?.role === "admin"; }
function canUseTenant(user) { return Number.isSafeInteger(Number(user?.organization_id)) && Number(user.organization_id)>0; }
async function validateTenantReferences(sql, table, body, tenant) {
  const checks = {
    customers: [["area_id", "areas"], ["customer_type_id", "customer_types"]],
    meters: [["customer_id", "customers"]],
    meter_readings: [["meter_id", "meters"]],
    meter_replacements: [["customer_id", "customers"], ["old_meter_id", "meters"], ["new_meter_id", "meters"]],
    tariff_brackets: [["customer_type_id", "customer_types"]],
    bills: [["customer_id", "customers"], ["meter_reading_id", "meter_readings"]],
    payments: [["bill_id", "bills"]]
  };
  for (const [field, refTable] of (checks[table] || [])) {
    if (body[field] === undefined || body[field] === null || body[field] === "") continue;
    if (!/^\d+$/.test(String(body[field]))) return `Kolom ${field} tidak valid.`;
    const rows = await sql.query(`SELECT id FROM "${refTable}" WHERE id=$1 AND organization_id=$2 LIMIT 1`, [Number(body[field]), tenant]);
    if (!rows.length) return `Data ${field} tidak ditemukan pada perusahaan ini.`;
  }
  return null;
}

export default {
  async fetch(request, env) {
    if(request.method==="OPTIONS") return new Response(null,{status:204,headers:cors});
    const url=new URL(request.url);
    if(url.pathname==="/api/health" && request.method==="GET") {
      try { if(!env.DATABASE_URL) throw new Error("DATABASE_URL belum dikonfigurasi"); const sql=neon(env.DATABASE_URL); const r=await sql`SELECT current_database() AS database, now() AS server_time`; return response({ok:true,database:r[0].database,server_time:r[0].server_time}); }
      catch(e){ console.error("health",e); return response({ok:false,error:"Koneksi database gagal."},503); }
    }
    if(!url.pathname.startsWith("/api/")) return env.ASSETS ? env.ASSETS.fetch(request) : response({error:"Binding ASSETS belum dikonfigurasi."},404);
    if(!env.JWT_SECRET || !env.DATABASE_URL) return response({error:"Konfigurasi server belum lengkap."},503);
    const sql=neon(env.DATABASE_URL);

    if(url.pathname==="/api/login" && request.method==="POST") {
      const body=await jsonBody(request); if(!body) return response({error:"JSON tidak valid."},400);
      const username=String(body.username||"").trim(); const password=String(body.password||"");
      if(!username||!password) return response({error:"Username dan password wajib diisi."},400);
      // Existing APP_USERS admin remains the temporary platform-owner bootstrap. Do not expose tenant access through this list.
      try {
        const legacy=JSON.parse(env.APP_USERS||"[]");
        const bootstrap=Array.isArray(legacy)&&legacy.find(x=>safeEqual(x?.username,username)&&safeEqual(x?.password,password)&&x?.role==="admin");
        if(bootstrap) {
          const token=await sign({sub:username,username,role:"owner",organization_id:null,exp:Math.floor(Date.now()/1000)+28800},env.JWT_SECRET);
          return response({token,username,role:"owner",expires_in:28800});
        }
      } catch { /* database login may still work if legacy secret is absent */ }
      try {
        const rows=await sql`SELECT id, organization_id, username, password_hash, role, is_active FROM app_users WHERE username=${username} LIMIT 1`;
        const u=rows[0];
        if(!u||!u.is_active||!['admin','staff'].includes(u.role)||!u.organization_id||!(await verifyPassword(password,u.password_hash))) return response({error:"Username atau password salah."},401);
        const org=await sql`SELECT id,status FROM organizations WHERE id=${u.organization_id} LIMIT 1`;
        if(!org[0]||org[0].status!=="active") return response({error:"Akun perusahaan tidak aktif."},403);
        const sub=await sql`SELECT status,current_period_end FROM subscriptions WHERE organization_id=${u.organization_id} LIMIT 1`;
        if(!sub[0]||sub[0].status!=="active"||!sub[0].current_period_end||String(sub[0].current_period_end).slice(0,10)<new Date().toISOString().slice(0,10)) return response({error:"Langganan perusahaan belum aktif atau sudah berakhir. Hubungi Owner Admin."},403);
        const token=await sign({sub:String(u.id),user_id:Number(u.id),username:u.username,role:u.role,organization_id:Number(u.organization_id),exp:Math.floor(Date.now()/1000)+28800},env.JWT_SECRET);
        return response({token,username:u.username,role:u.role,expires_in:28800});
      } catch(e){ console.error("login",e); return response({error:"Login gagal. Pastikan migrasi multi-perusahaan sudah dijalankan."},503); }
    }

    const user=await userFromRequest(request,env);
    if(!user) return response({error:"Silakan login terlebih dahulu."},401);
    const parts=url.pathname.split("/").filter(Boolean);

    // Owner Admin endpoints. Every mutation is role-checked here, server-side.
    if(parts[0]==="api" && parts[1]==="owner") {
      if(!isOwner(user)) return response({error:"Khusus Owner Admin."},403);
      try {
        if(parts.length===3 && parts[2]==="organizations" && request.method==="POST") {
          const b=await jsonBody(request);
          if(!b || !String(b.name||"").trim() || !/^[a-zA-Z0-9._-]{3,60}$/.test(String(b.admin_username||"")) || String(b.admin_password||"").length<6) return response({error:"Nama perusahaan, username admin (3-60 karakter), dan password minimal 6 karakter wajib diisi."},400);
          const slug=String(b.slug||b.name).toLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g,"").replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"").slice(0,80);
          if(!slug) return response({error:"Nama perusahaan tidak bisa dijadikan kode."},400);
          const orgs=await sql`INSERT INTO organizations(name,slug,email,phone,address,status) VALUES(${String(b.name).trim()},${slug},${b.email||null},${b.phone||null},${b.address||null},'active') RETURNING id,name,slug,status`;
          const org=orgs[0];
          await sql`INSERT INTO subscriptions(organization_id,status) VALUES(${org.id},'pending')`;
          const password_hash=await hashPassword(String(b.admin_password));
          await sql`INSERT INTO app_users(organization_id,username,email,password_hash,role,is_active) VALUES(${org.id},${String(b.admin_username)},${b.admin_email||b.email||null},${password_hash},'admin',true)`;
          return response({data:{...org,subscription_status:"pending"},message:"Perusahaan dibuat. Langganan masih pending sampai pembayaran dikonfirmasi."},201);
        }
        if(parts.length===3 && parts[2]==="tariffs" && request.method==="POST") {
          const b=await jsonBody(request); const price=Number(b?.price_per_customer); const date=String(b?.effective_from||"");
          if(!Number.isFinite(price)||price<0||!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(date)) return response({error:"Tarif dan tanggal berlaku YYYY-MM-DD wajib valid."},400);
          const previous=await sql`SELECT price_per_customer FROM subscription_tariffs WHERE effective_from < ${date} ORDER BY effective_from DESC LIMIT 1`;
          await sql`INSERT INTO subscription_tariffs(price_per_customer,effective_from,notes) VALUES(${price},${date},${b.notes||null})`;
          await sql`INSERT INTO subscription_tariff_history(old_price,new_price,effective_from,reason) VALUES(${previous[0]?.price_per_customer??null},${price},${date},${b.notes||'Perubahan tarif oleh Owner Admin'})`;
          return response({message:"Tarif tersimpan.",price_per_customer:price,effective_from:date},201);
        }
        if(parts.length===3 && parts[2]==="payments" && request.method==="POST") {
          const b=await jsonBody(request); const orgId=Number(b?.organization_id);
          if(!Number.isSafeInteger(orgId)||orgId<1) return response({error:"organization_id tidak valid."},400);
          const org=await sql`SELECT id FROM organizations WHERE id=${orgId} LIMIT 1`;
          const sub=await sql`SELECT id,status,current_period_end FROM subscriptions WHERE organization_id=${orgId} LIMIT 1`;
          if(!org[0]||!sub[0]) return response({error:"Perusahaan atau langganan tidak ditemukan."},404);
          const periodStart=String(b.period_start||new Date().toISOString().slice(0,10));
          const periodEnd=String(b.period_end||new Date(Date.now()+30*86400000).toISOString().slice(0,10));
          if(!/^\d{4}-\d{2}-\d{2}$/.test(periodStart)||!/^\d{4}-\d{2}-\d{2}$/.test(periodEnd)||periodEnd<periodStart) return response({error:"Periode tanggal tidak valid."},400);
          const tariff=await sql`SELECT price_per_customer FROM subscription_tariffs WHERE effective_from<=${periodStart} AND (effective_until IS NULL OR effective_until>=${periodStart}) ORDER BY effective_from DESC LIMIT 1`;
          if(!tariff[0]) return response({error:"Tarif belum ditetapkan untuk tanggal periode ini."},400);
          const countRows=await sql`SELECT COUNT(*)::int AS n FROM customers WHERE organization_id=${orgId} AND lower(status)='active'`;
          const count=Number(countRows[0]?.n||0), price=Number(tariff[0].price_per_customer), amount=count*price;
          const rows=await sql`INSERT INTO subscription_payments(organization_id,subscription_id,period_start,period_end,active_customer_count,price_per_customer,amount_due,status,notes) VALUES(${orgId},${sub[0].id},${periodStart},${periodEnd},${count},${price},${amount},'pending',${b.notes||null}) RETURNING *`;
          return response({data:rows[0]},201);
        }
        if(parts.length===4 && parts[2]==="payments" && /^\d+$/.test(parts[3]) && request.method==="PATCH") {
          const b=await jsonBody(request); if(b?.status!=="confirmed" && b?.status!=="rejected") return response({error:"status harus confirmed atau rejected."},400);
          const paymentId=Number(parts[3]);
          const p=await sql`SELECT * FROM subscription_payments WHERE id=${paymentId} LIMIT 1`;
          if(!p[0]) return response({error:"Pembayaran tidak ditemukan."},404);
          if(p[0].status!=="pending") return response({error:"Pembayaran ini sudah diproses."},409);
          if(b.status==="rejected") { const r=await sql`UPDATE subscription_payments SET status='rejected',notes=COALESCE(${b.notes||null},notes) WHERE id=${paymentId} AND status='pending' RETURNING *`; return response({data:r[0]}); }
          const paid=Number(b.amount_paid ?? p[0].amount_due);
          if(!Number.isFinite(paid)||paid<p[0].amount_due) return response({error:"Pembayaran belum mencukupi tagihan."},400);
          const now=new Date().toISOString();
          const r=await sql`UPDATE subscription_payments SET status='confirmed',amount_paid=${paid},payment_method=${b.payment_method||null},reference_no=${b.reference_no||null},paid_at=COALESCE(${b.paid_at||null}::timestamptz,now()),confirmed_at=now(),confirmed_by=NULL,notes=COALESCE(${b.notes||null},notes) WHERE id=${paymentId} AND status='pending' RETURNING *`;
          const start=String(r[0].period_start).slice(0,10), end=String(r[0].period_end).slice(0,10);
          await sql`UPDATE subscriptions SET status='active',started_on=COALESCE(started_on,${start}::date),current_period_start=${start}::date,current_period_end=${end}::date,next_due_on=(${end}::date + INTERVAL '1 day')::date,updated_at=now() WHERE id=${r[0].subscription_id}`;
          return response({data:r[0],message:"Pembayaran dikonfirmasi dan masa langganan diaktifkan."});
        }
        if(request.method==="GET") {
          if(parts.length===2) { const orgs=await sql`SELECT o.id,o.name,o.slug,o.email,o.phone,o.status,o.created_at,s.status AS subscription_status,s.current_period_start,s.current_period_end FROM organizations o LEFT JOIN subscriptions s ON s.organization_id=o.id ORDER BY o.id DESC`; return response({data:orgs}); }
          if(parts[2]==="tariffs" && parts.length===3) return response({data:await sql`SELECT * FROM subscription_tariffs ORDER BY effective_from DESC`});
          if(parts[2]==="payments" && parts.length===3) return response({data:await sql`SELECT p.*,o.name AS organization_name FROM subscription_payments p JOIN organizations o ON o.id=p.organization_id ORDER BY p.id DESC LIMIT 500`});
        }
        return response({error:"Endpoint Owner Admin tidak ditemukan atau method tidak didukung."},404);
      } catch(e) {
        // Log database diagnostics in Worker logs and show a bounded, useful message to Owner.
        console.error("owner endpoint", { message: e?.message, code: e?.code, constraint: e?.constraint, detail: e?.detail });
        const code = String(e?.code || "");
        const raw = String(e?.message || "");
        let message = "Operasi Owner Admin gagal.";
        if (code === "23505") {
          const constraint = String(e?.constraint || "");
          if (constraint.includes("username")) message = "Username Admin sudah digunakan. Gunakan username yang berbeda.";
          else if (constraint.includes("slug")) message = "Perusahaan dengan nama/kode tersebut sudah terdaftar. Periksa daftar perusahaan sebelum mencoba lagi.";
          else message = "Data duplikat terdeteksi. Periksa apakah perusahaan, tarif, atau tagihan sudah pernah tersimpan.";
        } else if (code === "23503") {
          message = "Relasi database belum lengkap. Periksa migrasi multi-tenant dan data yang dirujuk.";
        } else if (code === "23514" || code === "22P02" || code === "22007" || code === "22008") {
          message = "Ada nilai yang tidak sesuai format database. Periksa nama, username, tarif, dan tanggal.";
        } else if (/column .* does not exist|relation .* does not exist|undefined table|undefined column/i.test(raw)) {
          message = "Struktur database belum sesuai dengan Worker terbaru. Periksa apakah migrasi multi-tenant sudah dijalankan.";
        } else if (raw) {
          message += " Detail: " + raw.slice(0, 220);
        }
        return response({error:message},400);
      }
    }
    /* old read-only owner route replaced by the guarded block above */
    if(false && parts[0]==="api" && parts[1]==="owner" && isOwner(user) && request.method==="GET") {
      try {
        if(parts.length===2) {
          const orgs=await sql`SELECT o.id,o.name,o.slug,o.email,o.phone,o.status,o.created_at,s.status AS subscription_status,s.current_period_start,s.current_period_end FROM organizations o LEFT JOIN subscriptions s ON s.organization_id=o.id ORDER BY o.id DESC`;
          return response({data:orgs});
        }
        if(parts[2]==="tariffs" && parts.length===3) return response({data:await sql`SELECT * FROM subscription_tariffs ORDER BY effective_from DESC`});
        if(parts[2]==="payments" && parts.length===3) return response({data:await sql`SELECT p.*,o.name AS organization_name FROM subscription_payments p JOIN organizations o ON o.id=p.organization_id ORDER BY p.id DESC LIMIT 500`});
      } catch(e){ console.error("owner read",e); return response({error:"Gagal membaca data Owner Admin."},500); }
    }
    if(parts.length!==2||parts[0]!=="api"||!Object.hasOwn(TABLES,parts[1])) return response({error:"Endpoint tidak ditemukan."},404);
    if(isOwner(user)) return response({error:"Owner Admin mengelola perusahaan melalui endpoint owner, bukan data operasional tenant."},403);
    if(!canUseTenant(user)) return response({error:"Identitas perusahaan pada sesi tidak valid."},403);
    const table=parts[1], cols=TABLES[table], tenant=Number(user.organization_id), admin=isAdmin(user);

    try {
      // Subscription gate is checked server-side on every tenant data operation.
      const gate=await sql`SELECT o.status AS organization_status,s.status AS subscription_status,s.current_period_end FROM organizations o LEFT JOIN subscriptions s ON s.organization_id=o.id WHERE o.id=${tenant} LIMIT 1`;
      const g=gate[0];
      if(!g||g.organization_status!=="active") return response({error:"Perusahaan tidak aktif."},403);
      if(!g.subscription_status||g.subscription_status!=="active"||!g.current_period_end||String(g.current_period_end).slice(0,10)<new Date().toISOString().slice(0,10)) return response({error:"Langganan berakhir. Hubungi Owner Admin untuk perpanjangan."},402);

      if(request.method==="GET") {
        if(!admin&&!STAFF_READ.has(table)) return response({error:"Akses ditolak."},403);
        const requested=Number(url.searchParams.get("limit")||100), limit=Math.min(Math.max(Number.isFinite(requested)?requested:100,1),500);
        const rows=await sql.query(`SELECT ${cols.map(c=>`"${c}"`).join(",")} FROM "${table}" WHERE organization_id=$1 ORDER BY id DESC LIMIT $2`,[tenant,limit]);
        return response({data:rows});
      }
      if(request.method==="POST") {
        if(!admin&&!STAFF_WRITE.has(table)) return response({error:"Akses tulis ditolak."},403);
        const body=await jsonBody(request); if(!body||Array.isArray(body)||typeof body!=="object") return response({error:"Body JSON tidak valid."},400);
        if(table==="customers"&&!String(body.customer_no||"").trim()) { const r=new Uint8Array(4);crypto.getRandomValues(r);const suffix=Array.from(r,b=>b.toString(16).padStart(2,"0")).join("").toUpperCase();body.customer_no=`PEL-${new Date().toISOString().slice(0,10).replace(/-/g,"")}-${suffix}`; }
        if(table==="meter_readings"&&Number(body.current_reading)<Number(body.previous_reading)) return response({error:"Angka meter sekarang tidak boleh lebih kecil dari angka sebelumnya."},400);
        if(table==="payments"&&!(Number(body.amount)>0)) return response({error:"Nominal pembayaran harus lebih dari nol."},400);
        const referenceError=await validateTenantReferences(sql,table,body,tenant);
        if(referenceError) return response({error:referenceError},400);
        // organization_id is always supplied by the verified token, never by client input.
        const keys=Object.keys(body).filter(k=>cols.includes(k)&&!READ_ONLY.has(k)); keys.push("organization_id");
        const vals=keys.map(k=>k==="organization_id"?tenant:body[k]);
        if(keys.length===1) return response({error:"Tidak ada kolom yang bisa disimpan."},400);
        const rows=await sql.query(`INSERT INTO "${table}" (${keys.map(k=>`"${k}"`).join(",")}) VALUES (${keys.map((_,i)=>`$${i+1}`).join(",")}) RETURNING ${cols.map(c=>`"${c}"`).join(",")}`,vals);
        return response({data:rows[0]},201);
      }
      if(request.method==="PATCH"||request.method==="DELETE") {
        if(!admin) return response({error:"Hanya admin perusahaan yang boleh mengubah atau menghapus data."},403);
        const id=url.searchParams.get("id");if(!id||!/^\d+$/.test(id))return response({error:"ID tidak valid."},400);
        if(request.method==="DELETE") { const rows=await sql.query(`DELETE FROM "${table}" WHERE id=$1 AND organization_id=$2 RETURNING id`,[Number(id),tenant]);return rows.length?response({deleted:true}):response({error:"Data tidak ditemukan."},404); }
        const body=await jsonBody(request);if(!body||Array.isArray(body)||typeof body!=="object")return response({error:"JSON tidak valid."},400);
        const referenceError=await validateTenantReferences(sql,table,body,tenant);
        if(referenceError) return response({error:referenceError},400);
        const keys=Object.keys(body).filter(k=>cols.includes(k)&&!READ_ONLY.has(k));if(!keys.length)return response({error:"Tidak ada kolom yang bisa diubah."},400);
        const vals=keys.map(k=>body[k]);vals.push(Number(id),tenant);
        const rows=await sql.query(`UPDATE "${table}" SET ${keys.map((k,i)=>`"${k}"=$${i+1}`).join(",")} WHERE id=$${vals.length-1} AND organization_id=$${vals.length} RETURNING ${cols.map(c=>`"${c}"`).join(",")}`,vals);
        return rows.length?response({data:rows[0]}):response({error:"Data tidak ditemukan."},404);
      }
      return response({error:"Method tidak didukung."},405);
    } catch(e){ console.error(`MeterPAMS ${request.method} ${table} error:`,e);return response({error:"Operasi gagal. Pastikan migrasi multi-perusahaan sudah dijalankan dan data valid."},400); }
  }
};

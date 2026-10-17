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
const READ_ONLY = new Set(["id","created_at","usage_m3"]);
const STAFF_READ = new Set(["areas","customer_types","customers","meters","meter_readings","bills","payments","app_settings","tariff_brackets","meter_replacements"]);
const STAFF_WRITE = new Set(["meter_readings","payments"]);
const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Content-Type": "application/json; charset=utf-8"
};
const response = (data,status=200)=>new Response(JSON.stringify(data),{status,headers:cors});
const b64 = (bytes)=>btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
const enc = new TextEncoder();
async function sign(payload, secret) {
  const key = await crypto.subtle.importKey("raw",enc.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  const body=b64(enc.encode(JSON.stringify(payload)));
  const sig=b64(await crypto.subtle.sign("HMAC",key,enc.encode(body)));
  return `${body}.${sig}`;
}
async function verify(token, secret) {
  try {
    const [body,sig]=token.split(".");
    const key=await crypto.subtle.importKey("raw",enc.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
    const expected=b64(await crypto.subtle.sign("HMAC",key,enc.encode(body)));
    if(sig!==expected) return null;
    const p=JSON.parse(atob(body.replace(/-/g,"+").replace(/_/g,"/")));
    if(p.exp<Date.now()/1000) return null;
    return p;
  } catch { return null; }
}
function safeEqual(a,b) {
  if(typeof a!=="string"||typeof b!=="string"||a.length!==b.length) return false;
  let v=0; for(let i=0;i<a.length;i++) v|=a.charCodeAt(i)^b.charCodeAt(i); return v===0;
}
function userFromRequest(request,env) {
  const h=request.headers.get("Authorization")||"";
  const token=h.startsWith("Bearer ")?h.slice(7):"";
  return verify(token,env.JWT_SECRET);
}
export default {
 async fetch(request,env) {
  if(request.method==="OPTIONS") return new Response(null,{status:204,headers:cors});
  const url=new URL(request.url);
  if(url.pathname==="/api/health" && request.method==="GET") {
    try { const sql=neon(env.DATABASE_URL); const rows=await sql`select current_database() as database, now() as server_time`; return response({ok:true,database:rows[0].database,server_time:rows[0].server_time}); }
    catch(e){ return response({ok:false,error:"Database connection failed. Check DATABASE_URL secret."},503); }
  }
  if(url.pathname==="/api/login" && request.method==="POST") {
    if(!env.APP_USERS||!env.JWT_SECRET) return response({error:"Authentication secrets are not configured."},503);
    let body; try{body=await request.json()}catch{return response({error:"Invalid JSON"},400)}
    let users; try{users=JSON.parse(env.APP_USERS)}catch{return response({error:"APP_USERS secret must be valid JSON."},500)}
    const u=users.find(x=>safeEqual(x.username,body.username)&&safeEqual(x.password,body.password));
    if(!u||!["admin","staff"].includes(u.role)) return response({error:"Username atau password salah."},401);
    const token=await sign({sub:u.username,role:u.role,exp:Math.floor(Date.now()/1000)+60*60*8},env.JWT_SECRET);
    return response({token,username:u.username,role:u.role,expires_in:28800});
  }
  if(!url.pathname.startsWith("/api/")) {
    if(env.ASSETS) return env.ASSETS.fetch(request);
    return response({error:"Static asset binding ASSETS belum dikonfigurasi."},404);
  }
  const user=await userFromRequest(request,env);
  if(!user) return response({error:"Silakan login terlebih dahulu."},401);
  const parts=url.pathname.split("/").filter(Boolean);
  if(parts.length!==2||parts[0]!=="api"||!Object.hasOwn(TABLES,parts[1])) return response({error:"Endpoint tidak ditemukan."},404);
  const table=parts[1], cols=TABLES[table];
  const isAdmin=user.role==="admin";
  if(request.method==="GET") {
    if(!isAdmin&&!STAFF_READ.has(table)) return response({error:"Akses ditolak."},403);
    try {
      const sql=neon(env.DATABASE_URL);
      const limit=Math.min(Math.max(Number(url.searchParams.get("limit")||100),1),500);
      // Table name and columns come only from the allowlist above.
      const rows=await sql.query(`SELECT ${cols.map(c=>'"'+c+'"').join(", ")} FROM "${table}" ORDER BY "id" DESC LIMIT $1`,[limit]);
      return response({data:rows});
    } catch(e) { return response({error:"Gagal membaca data database."},500); }
  }
  if(request.method==="POST") {
    if(!isAdmin&&!STAFF_WRITE.has(table)) return response({error:"Akses tulis ditolak."},403);
    let body; try{body=await request.json()}catch{return response({error:"Invalid JSON"},400)}
    if(!body||Array.isArray(body)||typeof body!=="object") return response({error:"Body harus berupa objek JSON."},400);
    const keys=Object.keys(body).filter(k=>cols.includes(k)&&!READ_ONLY.has(k));
    if(!keys.length) return response({error:"Tidak ada kolom yang bisa disimpan."},400);
    if(table==="meter_readings" && Number(body.current_reading)<Number(body.previous_reading)) return response({error:"Angka meter sekarang tidak boleh lebih kecil dari angka sebelumnya."},400);
    if(table==="payments" && !(Number(body.amount)>0)) return response({error:"Nominal pembayaran harus lebih dari nol."},400);
    try {
      const sql=neon(env.DATABASE_URL);
      const vals=keys.map(k=>body[k]);
      const q=`INSERT INTO "${table}" (${keys.map(k=>'"'+k+'"').join(",")}) VALUES (${keys.map((_,i)=>`$${i+1}`).join(",")}) RETURNING ${cols.map(c=>'"'+c+'"').join(",")}`;
      const rows=await sql.query(q,vals);
      return response({data:rows[0]},201);
    } catch(e) { return response({error:"Gagal menyimpan data. Periksa relasi wajib dan format kolom."},400); }
  }
  if(request.method==="PATCH"||request.method==="DELETE") {
    if(!isAdmin) return response({error:"Hanya admin yang boleh mengubah atau menghapus data."},403);
    const id=url.searchParams.get("id");
    if(!id||!/^\d+$/.test(id)) return response({error:"ID tidak valid."},400);
    try {
      const sql=neon(env.DATABASE_URL);
      if(request.method==="DELETE") {
        const rows=await sql.query(`DELETE FROM "${table}" WHERE id=$1 RETURNING id`,[Number(id)]);
        return rows.length?response({deleted:true}):response({error:"Data tidak ditemukan."},404);
      }
      let body; try{body=await request.json()}catch{return response({error:"Invalid JSON"},400)}
      const keys=Object.keys(body||{}).filter(k=>cols.includes(k)&&!READ_ONLY.has(k));
      if(!keys.length) return response({error:"Tidak ada kolom yang bisa diubah."},400);
      const vals=keys.map(k=>body[k]); vals.push(Number(id));
      const rows=await sql.query(`UPDATE "${table}" SET ${keys.map((k,i)=>`"${k}"=$${i+1}`).join(",")} WHERE id=$${vals.length} RETURNING ${cols.map(c=>'"'+c+'"').join(",")}`,vals);
      return rows.length?response({data:rows[0]}):response({error:"Data tidak ditemukan."},404);
    } catch(e) { return response({error:"Perubahan gagal. Periksa relasi dan aturan database."},400); }
  }
  return response({error:"Method tidak didukung."},405);
 }
};

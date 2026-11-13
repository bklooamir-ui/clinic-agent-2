require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, "clinic.sqlite"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','doctor','patient')),
 specialty TEXT DEFAULT '',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS appointments (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 patient_id INTEGER NOT NULL,
 doctor_id INTEGER NOT NULL,
 date TEXT NOT NULL,
 time TEXT NOT NULL,
 reason TEXT DEFAULT '',
 status TEXT DEFAULT 'در انتظار',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(patient_id) REFERENCES users(id),
 FOREIGN KEY(doctor_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS messages (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 role TEXT NOT NULL,
 content TEXT NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);
const count = db.prepare("SELECT COUNT(*) n FROM users").get().n;
if (!count) {
  const seed = db.prepare("INSERT INTO users(name,email,password_hash,role,specialty) VALUES(?,?,?,?,?)");
  seed.run("مدیر کلینیک", "admin@clinic.local", bcrypt.hashSync("Admin123!", 10), "admin", "");
  seed.run("دکتر نسترن احمدی", "doctor@clinic.local", bcrypt.hashSync("Doctor123!", 10), "doctor", "پزشک عمومی");
  seed.run("بیمار آزمایشی", "patient@clinic.local", bcrypt.hashSync("Patient123!", 10), "patient", "");
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: dataDir }),
  secret: process.env.SESSION_SECRET || "development-only-change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 8 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/", rateLimit({ windowMs: 60_000, limit: 100, standardHeaders: true, legacyHeaders: false }));

const safeUser = u => ({ id:u.id, name:u.name, email:u.email, role:u.role, specialty:u.specialty });
function auth(req,res,next){ if(!req.session.user) return res.status(401).json({error:"ابتدا وارد حساب شوید."}); next(); }
function roles(...allowed){ return (req,res,next)=>{ if(!req.session.user || !allowed.includes(req.session.user.role)) return res.status(403).json({error:"اجازه دسترسی ندارید."}); next(); }; }
function redFlag(text){
 const t = String(text || "").toLowerCase();
 const patterns = [
  /درد شدید قفسه سینه|فشار قفسه سینه|chest pain/,
  /تنگی نفس شدید|نمی.?توانم نفس|shortness of breath/,
  /علائم سکته|افتادگی صورت|اختلال ناگهانی گفتار|stroke/,
  /بیهوش|از هوش رفت|unconscious/,
  /خونریزی شدید|خونریزی بند نمی.?آید/,
  /اقدام به خودکشی|قصد خودکشی|suicid/
 ];
 return patterns.some(p=>p.test(t));
}

app.get("/api/health", (req,res)=>res.json({ok:true, service:"Clinic Agent 2"}));
app.post("/api/auth/login", (req,res)=>{
 const {email,password}=req.body || {};
 const user=db.prepare("SELECT * FROM users WHERE email=?").get(String(email||"").trim().toLowerCase());
 if(!user || !bcrypt.compareSync(String(password||""),user.password_hash)) return res.status(401).json({error:"ایمیل یا رمز عبور نادرست است."});
 req.session.user=safeUser(user); res.json({user:req.session.user});
});
app.get("/api/auth/me",(req,res)=>res.json({user:req.session.user||null}));
app.post("/api/auth/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.get("/api/dashboard",auth,(req,res)=>{
 const u=req.session.user;
 const stats={
  patients: db.prepare("SELECT COUNT(*) n FROM users WHERE role='patient'").get().n,
  doctors: db.prepare("SELECT COUNT(*) n FROM users WHERE role='doctor'").get().n,
  appointments: db.prepare("SELECT COUNT(*) n FROM appointments").get().n,
  pending: db.prepare("SELECT COUNT(*) n FROM appointments WHERE status='در انتظار'").get().n
 };
 let appointments;
 if(u.role==="patient") appointments=db.prepare(`SELECT a.*, d.name doctor_name FROM appointments a JOIN users d ON d.id=a.doctor_id WHERE a.patient_id=? ORDER BY a.date DESC,a.time DESC LIMIT 20`).all(u.id);
 else if(u.role==="doctor") appointments=db.prepare(`SELECT a.*, p.name patient_name FROM appointments a JOIN users p ON p.id=a.patient_id WHERE a.doctor_id=? ORDER BY a.date DESC,a.time DESC LIMIT 20`).all(u.id);
 else appointments=db.prepare(`SELECT a.*, p.name patient_name,d.name doctor_name FROM appointments a JOIN users p ON p.id=a.patient_id JOIN users d ON d.id=a.doctor_id ORDER BY a.date DESC,a.time DESC LIMIT 20`).all();
 res.json({stats,appointments});
});
app.get("/api/doctors",auth,(req,res)=>res.json(db.prepare("SELECT id,name,specialty FROM users WHERE role='doctor' ORDER BY name").all()));
app.get("/api/patients",auth,roles("admin","doctor"),(req,res)=>res.json(db.prepare("SELECT id,name,email,created_at FROM users WHERE role='patient' ORDER BY name").all()));
app.post("/api/appointments",auth,(req,res)=>{
 const {doctorId,date,time,reason}=req.body||{};
 if(!doctorId||!date||!time) return res.status(400).json({error:"پزشک، تاریخ و ساعت الزامی است."});
 if(req.session.user.role!=="patient" && req.session.user.role!=="admin") return res.status(403).json({error:"فقط بیمار یا مدیر می‌تواند نوبت ثبت کند."});
 const patientId=req.session.user.role==="patient"?req.session.user.id:Number(req.body.patientId);
 const doctor=db.prepare("SELECT id FROM users WHERE id=? AND role='doctor'").get(Number(doctorId));
 const patient=db.prepare("SELECT id FROM users WHERE id=? AND role='patient'").get(patientId);
 if(!doctor||!patient) return res.status(400).json({error:"پزشک یا بیمار معتبر نیست."});
 const info=db.prepare("INSERT INTO appointments(patient_id,doctor_id,date,time,reason) VALUES(?,?,?,?,?)").run(patientId,Number(doctorId),date,time,String(reason||"").slice(0,500));
 res.json({ok:true,id:info.lastInsertRowid});
});
app.patch("/api/appointments/:id",auth,roles("admin","doctor"),(req,res)=>{
 const status=String(req.body.status||"");
 if(!["در انتظار","تأیید شده","انجام شده","لغو شده"].includes(status)) return res.status(400).json({error:"وضعیت نامعتبر است."});
 const a=db.prepare("SELECT * FROM appointments WHERE id=?").get(Number(req.params.id));
 if(!a || (req.session.user.role==="doctor" && a.doctor_id!==req.session.user.id)) return res.status(404).json({error:"نوبت پیدا نشد."});
 db.prepare("UPDATE appointments SET status=? WHERE id=?").run(status,a.id); res.json({ok:true});
});
app.get("/api/users",auth,roles("admin"),(req,res)=>res.json(db.prepare("SELECT id,name,email,role,specialty,created_at FROM users ORDER BY id DESC").all()));
app.post("/api/users",auth,roles("admin"),(req,res)=>{
 const {name,email,password,role,specialty}=req.body||{};
 if(!name||!email||!password||!["admin","doctor","patient"].includes(role)||String(password).length<8) return res.status(400).json({error:"اطلاعات نامعتبر است؛ رمز عبور حداقل ۸ کاراکتر باشد."});
 try{
  const info=db.prepare("INSERT INTO users(name,email,password_hash,role,specialty) VALUES(?,?,?,?,?)").run(String(name).slice(0,100),String(email).trim().toLowerCase(),bcrypt.hashSync(password,10),role,String(specialty||"").slice(0,100));
  res.json({ok:true,id:info.lastInsertRowid});
 }catch(e){res.status(409).json({error:"این ایمیل قبلاً ثبت شده است."});}
});

app.post("/api/ai/chat",auth,rateLimit({windowMs:60_000,limit:20}),async(req,res)=>{
 const question=String(req.body.message||"").trim().slice(0,3000);
 if(!question) return res.status(400).json({error:"سؤال را بنویسید."});
 const urgent=redFlag(question);
 if(urgent) return res.json({
  urgent:true,
  answer:"ممکن است این علائم نشانه وضعیت اورژانسی باشند. لطفاً منتظر پاسخ آنلاین نمانید؛ همین حالا با اورژانس محل زندگی خود تماس بگیرید یا به نزدیک‌ترین مرکز اورژانس مراجعه کنید. اگر تنها هستید از فردی مطمئن کمک بخواهید. این سامانه برای تشخیص یا مدیریت وضعیت اورژانسی مناسب نیست."
 });
 if(!process.env.OPENAI_API_KEY) return res.json({
  answer:"برای فعال شدن پاسخ‌گویی هوشمند، مدیر سامانه باید OPENAI_API_KEY را در تنظیمات محیطی سرور وارد کند. تا آن زمان می‌توانم فقط راهنمایی عمومی محدودی ارائه کنم: لطفاً برای تفسیر علائم، آزمایش یا دارو با پزشک یا داروساز مشورت کنید. در صورت شدید یا ناگهانی بودن علائم، فوراً کمک پزشکی بگیرید.",
  configured:false
 });
 try{
  const base=(process.env.OPENAI_BASE_URL||"https://api.openai.com/v1").replace(/\/$/,"");
  const response=await fetch(base+"/chat/completions",{
   method:"POST",
   headers:{"Authorization":"Bearer "+process.env.OPENAI_API_KEY,"Content-Type":"application/json"},
   body:JSON.stringify({
    model:process.env.OPENAI_MODEL||"gpt-4o-mini",
    temperature:0.2,
    messages:[
     {role:"system",content:"تو دستیار اطلاعات سلامت یک کلینیک هستی و به فارسی پاسخ می‌دهی. فقط آموزش عمومی و اطلاعات پزشکی محتاطانه ارائه کن؛ تشخیص قطعی، تجویز دارو، تغییر دوز یا جایگزینی پزشک ممنوع است. اگر اطلاعات کافی نیست سؤال روشن‌کننده بپرس. درباره علائم هشدار، توصیه به اورژانس بده. عدم قطعیت را شفاف بگو. برای ادعاهای پزشکی منابع معتبر مانند WHO، NHS، MedlinePlus و راهنماهای رسمی را نام ببر، اما هرگز منبع یا نقل‌قول ساختگی نساز. اطلاعات شخصی غیرضروری نخواه. پاسخ کوتاه، روشن و قابل فهم باشد. این پاسخ جایگزین ویزیت پزشک نیست."},
     {role:"user",content:question}
    ]
   })
  });
  const data=await response.json();
  if(!response.ok) throw new Error(data.error?.message||"AI provider error");
  res.json({answer:data.choices?.[0]?.message?.content||"پاسخی دریافت نشد.",configured:true});
 }catch(e){res.status(502).json({error:"در حال حاضر ارتباط با سرویس هوش مصنوعی برقرار نشد. لطفاً بعداً تلاش کنید."});}
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`Clinic Agent 2 running on ${PORT}`));

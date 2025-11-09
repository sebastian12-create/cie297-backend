import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

const app = express();
app.use(express.json());
app.use(cors({ origin: true, credentials: true }));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";

// Ruta de salud
app.get("/api/health", (_req, res) => res.json({ ok: true }));

// Usuarios mock
const USERS = [
  { email:"admin@cie297.mil", password:"123456", nombres:"Admin", grado:"CNL", is_admin:true },
  { email:"user@cie297.mil",  password:"123456", nombres:"Oper",  grado:"SGTO", is_admin:false }
];

let REPORTS = [];
let ACCESOS = [];

function auth(req,res,next){
  const token = (req.header("Authorization")||"").replace(/^Bearer\s+/i,"").trim();
  if(!token) return res.status(401).json({message:"No token"});
  try{ req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch{ return res.status(401).json({message:"Token inválido"}); }
}

app.post("/api/login", (req,res)=>{
  const {email,password} = req.body||{};
  const u = USERS.find(x=>x.email===email && x.password===password);
  if(!u) return res.status(401).json({message:"Credenciales inválidas"});
  const token = jwt.sign({email:u.email,is_admin:u.is_admin,nombres:u.nombres,grado:u.grado}, JWT_SECRET, {expiresIn:"1d"});
  ACCESOS.push({ created_at:new Date().toISOString(), email:u.email, estado:"OK" });
  res.json({ token, user:{email:u.email,is_admin:u.is_admin,nombres:u.nombres,grado:u.grado} });
});

app.get("/api/me", auth, (req,res)=>res.json({ user:req.user }));

app.post("/api/register", (req,res)=>{
  const { email,password,nombres,grado } = req.body||{};
  if(!email || !password) return res.status(400).json({message:"Faltan datos"});
  if(USERS.some(u=>u.email===email)) return res.status(409).json({message:"Ya existe"});
  USERS.push({ email,password,nombres:nombres||"",grado:grado||"",is_admin:false });
  res.json({ ok:true, email });
});

app.post("/api/reports", auth, (req,res)=>{
  const { tipo,nivel,descripcion,lat,lng } = req.body||{};
  const item = { id:String(Date.now()), created_at:new Date().toISOString(), fecha:new Date().toISOString(),
    tipo:tipo||"OTROS", nivel:(nivel||"MEDIA").toUpperCase(), descripcion:descripcion||"", lat:lat??null, lng:lng??null, usuario:req.user.email };
  REPORTS.push(item);
  res.json({ ok:true, item });
});

app.get("/api/admin/alerts", auth, (req,res)=>{
  const limit = Math.min(Number(req.query.limit||10), 5000);
  res.json({ items: REPORTS.slice(-limit).reverse() });
});

app.get("/api/admin/access", auth, (_req,res)=>{
  const limit = 50;
  res.json({ items: ACCESOS.slice(-limit).reverse() });
});

// Raíz informativa
app.get("/", (_req,res)=>res.send("API CIE-297 OK"));

app.listen(PORT, ()=>console.log("API ON", PORT));

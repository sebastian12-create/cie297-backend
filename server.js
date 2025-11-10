// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// --- ENV
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secreto-largo-123';

// --- Almacenamiento en memoria (demo)
const users = new Map();       // email -> { email, nombre, password, grado, fuerza, is_admin }
const accessLog = [];          // {fecha,email,nombre,ip,estado}
const blocked = new Set();     // emails bloqueados
const alerts = [];             // reportes enviados manualmente
const agents = new Map();      // email -> {email, lat, lng, color}

// Usuarios semilla (puedes quitarlos si deseas)
if (!users.has('admin@cie297.mil')) {
  users.set('admin@cie297.mil', {
    email: 'admin@cie297.mil', nombre: 'Admin', password: '123456',
    grado: 'WW', fuerza: 'MA', is_admin: true
  });
}
if (!users.has('user@cie297.mil')) {
  users.set('user@cie297.mil', {
    email: 'user@cie297.mil', nombre: 'Operador', password: '123456',
    grado: 'WW', fuerza: 'MA', is_admin: false
  });
}

// --- Helpers
function sign(user){
  const payload = { email: user.email, is_admin: user.is_admin, nombre: user.nombre };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '12h' });
}
function auth(req,res,next){
  const h = req.headers.authorization || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
  try{
    const data = jwt.verify(tok, JWT_SECRET);
    req.user = data;
    next();
  }catch(e){
    return res.status(401).json({ message: 'No autorizado' });
  }
}
function clientIp(req){
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
}

// --- Rutas públicas
app.get('/', (req,res)=>res.json({ ok:true, service:'CIE-297 API' }));

app.post('/login', (req,res)=>{
  const { email, password } = req.body||{};
  const u = users.get(String(email||'').toLowerCase());
  if(!u || u.password !== password){
    accessLog.push({ fecha: Date.now(), email, nombre: '', ip: clientIp(req), estado:'DENEGADO' });
    return res.status(401).json({ message:'Credenciales inválidas' });
  }
  if(blocked.has(u.email)){
    accessLog.push({ fecha: Date.now(), email: u.email, nombre: u.nombre, ip: clientIp(req), estado:'BLOQUEADO' });
    return res.status(403).json({ message:'Usuario bloqueado' });
  }
  const token = sign(u);
  accessLog.push({ fecha: Date.now(), email: u.email, nombre: u.nombre, ip: clientIp(req), estado:'OK' });
  return res.json({ token, user: { email: u.email, nombre: u.nombre, is_admin: u.is_admin } });
});

app.post('/register', (req,res)=>{
  const { nombre, email, password, grado, fuerza } = req.body||{};
  const key = String(email||'').toLowerCase();
  if(!nombre || !email || !password) return res.status(400).json({ message:'Datos incompletos' });
  if(users.has(key)) return res.status(409).json({ message:'Ya existe el usuario' });
  users.set(key, { email:key, nombre, password, grado, fuerza, is_admin:false });
  return res.json({ ok:true });
});

// --- Rutas protegidas
app.post('/position', auth, (req,res)=>{
  const { lat, lng, color } = req.body||{};
  agents.set(req.user.email, { email:req.user.email, lat:Number(lat), lng:Number(lng), color:color||'VERDE' });
  return res.json({ ok:true });
});

app.get('/agents', auth, (req,res)=>{
  return res.json({ agents: Array.from(agents.values()) });
});

app.post('/reports', auth, (req,res)=>{
  const body = req.body||{};
  const rec = {
    id: alerts.length + 1,
    fecha: Date.now(),
    usuario: { email: req.user.email },
    ...body
  };
  alerts.unshift(rec); // último primero
  return res.json({ ok:true, id: rec.id });
});

app.get('/admin/alerts', auth, (req,res)=>{
  // Devuelve SOLO las enviadas manualmente (no simula)
  return res.json({ alertas: alerts });
});

app.get('/admin/access', auth, (req,res)=>{
  return res.json({ accesos: accessLog });
});

app.post('/admin/access/block', auth, (req,res)=>{
  const { email } = req.body||{};
  if(!email) return res.status(400).json({ message:'Email requerido' });
  blocked.add(String(email).toLowerCase());
  return res.json({ ok:true });
});

app.delete('/admin/access', auth, (req,res)=>{
  const { email } = req.body||{};
  const target = String(email||'').toLowerCase();
  const remain = accessLog.filter(a => String(a.email||'').toLowerCase() !== target);
  accessLog.length = 0; accessLog.push(...remain);
  return res.json({ ok:true });
});

// --- Inicio
app.listen(PORT, ()=>console.log(`CIE-297 API escuchando en :${PORT}`));



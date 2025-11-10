// CIE-297 Backend API (modificado según 16 puntos)
// Express + CORS + JWT. Reportes manuales (con lat/lng y todos los campos).
// Mapa: posiciones de agentes (al iniciar sesión/actualizar). Accesos con bloquear/eliminar.

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors({ origin: true, credentials: true }));

const JWT_SECRET = process.env.JWT_SECRET || 'super-secreto-largo-123';
const PORT = process.env.PORT || 3000;

// --- Datos en memoria ---
let USERS = [
  { email:'admin@cie297.mil', password:'123456', nombre:'Admin', grado:'W1', fuerza:'MA', is_admin:true },
  { email:'user@cie297.mil',  password:'123456', nombre:'Operador', grado:'W2', fuerza:'MB', is_admin:false }
];

let REPORTS = []; // cada item: ver schema abajo
let ACCESOS = []; // {fecha, email, nombre, ip, estado}
let AGENTS  = []; // {email, lat, lng, color, ts}

// --- Helpers / Auth ---
function sign(user){
  return jwt.sign({ email:user.email, is_admin: !!user.is_admin, nombre: user.nombre||'' }, JWT_SECRET, { expiresIn:'1d' });
}
function auth(req,res,next){
  const h = req.headers['authorization'] || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if(!token) return res.status(401).json({ message:'No autorizado' });
  try{ req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch(e){ return res.status(401).json({ message:'Token inválido' }); }
}

// --- Rutas básicas ---
app.get('/api/health', (req,res)=> res.json({ ok:true }));

app.post('/api/register', (req,res)=>{
  const { email, password, nombre, grado, fuerza } = req.body || {};
  if(!email || !password || !nombre) return res.status(400).json({ message:'Faltan datos' });
  const exists = USERS.some(u => u.email.toLowerCase()===String(email).toLowerCase());
  if(exists) return res.status(409).json({ message:'El usuario ya existe' });
  USERS.push({ email, password, nombre, grado: grado||'W1', fuerza: fuerza||'MA', is_admin:false });
  return res.status(201).json({ ok:true, message:'Registrado' });
});

app.post('/api/login', (req,res)=>{
  const { email, password } = req.body || {};
  const user = USERS.find(u => u.email.toLowerCase()===String(email||'').toLowerCase() && u.password===password);
  if(!user) return res.status(401).json({ message:'Credenciales inválidas' });

  const token = sign(user);
  ACCESOS.push({
    fecha: Date.now(),
    email: user.email,
    nombre: user.nombre || '',
    ip: req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '-',
    estado: 'OK'
  });

  return res.json({ token, user: { email:user.email, nombre:user.nombre, is_admin: !!user.is_admin } });
});

// --- Posición de agente (para el mapa) ---
app.post('/api/position', auth, (req,res)=>{
  const { lat, lng, color } = req.body || {};
  if(typeof lat!=='number' || typeof lng!=='number'){
    return res.status(400).json({ message:'Lat/Lng numéricos requeridos' });
  }
  // upsert por email
  const idx = AGENTS.findIndex(a => a.email===req.user.email);
  const item = { email:req.user.email, lat, lng, color: (color||'VERDE'), ts: Date.now() };
  if(idx>=0) AGENTS[idx]=item; else AGENTS.push(item);
  return res.json({ ok:true });
});

app.get('/api/agents', auth, (req,res)=>{
  // opcional: limpiar agentes viejos (inactivos > 1 día)
  const cutoff = Date.now() - 24*60*60*1000;
  AGENTS = AGENTS.filter(a => (a.ts||0) >= cutoff);
  return res.json({ agents: AGENTS });
});

// --- Reportes manuales ---
/*
Schema del reporte (ejemplo):
{
  fecha:Number, nivel:String, operacion:String, color:String,
  pais_ciudad:String, lugar_code:String, personalidad:String,
  unidad_policial:String, accion_oponente:String, material_equipo:String,
  transporte:String, otros:String, clasificacion_seg:String, tipo_documento:String,
  detalle:String, lat:Number, lng:Number,
  usuario:{ email, nombre }
}
*/
app.post('/api/reports', auth, (req,res)=>{
  const b = req.body || {};
  const required = ['nivel','operacion','pais_ciudad','detalle'];
  for(const k of required){ if(!b[k]) return res.status(400).json({ message:`Falta ${k}` }); }

  const rep = {
    fecha: Date.now(),
    nivel: b.nivel,
    operacion: b.operacion,
    color: b.color || '',
    pais_ciudad: b.pais_ciudad || '',
    lugar_code: b.lugar_code || '',
    personalidad: b.personalidad || '',
    unidad_policial: b.unidad_policial || '',
    accion_oponente: b.accion_oponente || '',
    material_equipo: b.material_equipo || '',
    transporte: b.transporte || '',
    otros: b.otros || '',
    clasificacion_seg: b.clasificacion_seg || '',
    tipo_documento: b.tipo_documento || '',
    detalle: b.detalle || '',
    lat: typeof b.lat==='number' ? b.lat : null,
    lng: typeof b.lng==='number' ? b.lng : null,
    usuario: { email:req.user.email, nombre:req.user.nombre||'' }
  };
  REPORTS.unshift(rep);
  return res.status(201).json({ ok:true, rep });
});

// --- Vistas de alertas (solo lo manual guardado arriba) ---
app.get('/api/admin/alerts', auth, (req,res)=>{
  if(!req.user?.is_admin){
    // usuarios ven lista simple
    return res.json({ alertas: REPORTS.slice(0,500) });
  }
  // admin ve todo (cap)
  return res.json({ alertas: REPORTS.slice(0,2000) });
});

// --- Accesos con bloquear/eliminar ---
app.get('/api/admin/access', auth, (req,res)=>{
  if(!req.user?.is_admin) return res.status(403).json({ message:'Solo admin' });
  return res.json({ accesos: ACCESOS.slice(-2000).reverse() });
});

app.post('/api/admin/access/block', auth, (req,res)=>{
  if(!req.user?.is_admin) return res.status(403).json({ message:'Solo admin' });
  const { email } = req.body || {};
  if(!email) return res.status(400).json({ message:'email requerido' });
  let updated=0;
  ACCESOS = ACCESOS.map(a=>{
    if((a.email||'').toLowerCase()===String(email).toLowerCase()) { updated++; return { ...a, estado:'BLOQUEADO' }; }
    return a;
  });
  return res.json({ ok:true, updated });
});

app.delete('/api/admin/access', auth, (req,res)=>{
  if(!req.user?.is_admin) return res.status(403).json({ message:'Solo admin' });
  const { email } = req.body || {};
  if(!email) return res.status(400).json({ message:'email requerido' });
  const before = ACCESOS.length;
  ACCESOS = ACCESOS.filter(a => (a.email||'').toLowerCase() !== String(email).toLowerCase());
  return res.json({ ok:true, removed: before - ACCESOS.length });
});

// --- Inicio ---
app.listen(PORT, ()=> console.log(`CIE-297 backend escuchando en :${PORT}`));


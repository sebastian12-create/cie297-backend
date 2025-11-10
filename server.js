// CIE-297 Backend API
// Express + CORS + JWT, con endpoints de login, registro, reportes,
// vistas de admin (alertas y accesos) y endpoints opcionales de bloqueo/eliminación.

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();

// Config básica
app.use(express.json());
app.use(cors({ origin: true, credentials: true }));

const JWT_SECRET = process.env.JWT_SECRET || 'super-secreto-largo-123';
const PORT = process.env.PORT || 3000;

// --- Datos en memoria (para demo). Reemplaza por DB cuando quieras. ---
let USERS = [
  // Usuarios de prueba
  { email:'admin@cie297.mil', password:'123456', nombre:'Admin', grado:'W1', fuerza:'MA', is_admin:true },
  { email:'user@cie297.mil',  password:'123456', nombre:'Operador', grado:'W2', fuerza:'MB', is_admin:false }
];

let REPORTS = []; // {fecha, nivel, operacion, lugar, detalle, usuario:{email,nombre}}
let ACCESOS = []; // {fecha, email, nombre, ip, estado}

// --- Helpers ---
function sign(user){
  // token válido 1 día
  return jwt.sign({ email:user.email, is_admin: !!user.is_admin, nombre: user.nombre||'' }, JWT_SECRET, { expiresIn:'1d' });
}

function auth(req,res,next){
  const h = req.headers['authorization'] || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if(!token) return res.status(401).json({ message:'No autorizado' });
  try{
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  }catch(e){
    return res.status(401).json({ message:'Token inválido' });
  }
}

// --- Rutas ---
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
  // registramos acceso
  ACCESOS.push({
    fecha: Date.now(),
    email: user.email,
    nombre: user.nombre || '',
    ip: req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '-',
    estado: 'OK'
  });

  return res.json({
    token,
    user: { email:user.email, nombre:user.nombre, is_admin: !!user.is_admin }
  });
});

app.post('/api/reports', auth, (req,res)=>{
  const { nivel, operacion, lugar, detalle } = req.body || {};
  if(!nivel || !operacion || !lugar || !detalle){
    return res.status(400).json({ message:'Faltan campos del reporte' });
  }
  const rep = {
    fecha: Date.now(),
    nivel, operacion, lugar, detalle,
    usuario: { email: req.user.email, nombre: req.user.nombre||'' }
  };
  REPORTS.unshift(rep); // último primero
  return res.status(201).json({ ok:true, id: Date.now(), rep });
});

// --- Admin ---
app.get('/api/admin/alerts', auth, (req,res)=>{
  if(!req.user?.is_admin){
    // Si no es admin, igual devolvemos reportes (vista simple)
    return res.json({ alertas: REPORTS.slice(0,100) });
  }
  // Para admin devolvemos todos (cap a 1000)
  return res.json({ alertas: REPORTS.slice(0,1000) });
});

app.get('/api/admin/access', auth, (req,res)=>{
  if(!req.user?.is_admin) return res.status(403).json({ message:'Solo admin' });
  // máx 1000 por seguridad
  return res.json({ accesos: ACCESOS.slice(-1000).reverse() });
});

// --- Opcional: habilitar acciones admin (bloquear / eliminar) ---
app.post('/api/admin/access/block', auth, (req,res)=>{
  if(!req.user?.is_admin) return res.status(403).json({ message:'Solo admin' });
  const { email } = req.body || {};
  if(!email) return res.status(400).json({ message:'email requerido' });
  let updated = 0;
  ACCESOS = ACCESOS.map(a=>{
    if((a.email||'').toLowerCase() === String(email).toLowerCase()){
      updated++; return { ...a, estado:'BLOQUEADO' };
    }
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
app.listen(PORT, ()=> {
  console.log(`CIE-297 backend escuchando en :${PORT}`);
});

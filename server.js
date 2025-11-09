import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import { stringify } from 'csv-stringify';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'devkey';
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';

app.use(cors({ origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN }));
app.use(express.json());

// --- almacenamiento en memoria (demo) ---
const db = {
  users: [],            // {id, email, password, nombres, apellidos, grado, fuerza, especialidad, is_admin}
  alerts: [],           // {id, created_at, usuario, nivel, operacion, descripcion, lat, lng, ...extras}
  accessLog: [],        // {created_at, email, estado}
  blocked: new Set(),   // emails bloqueados
  agents: []            // {email, rol, lat, lng, updated_at}
};

let idCounter = 1;

// --- helpers ---
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    if (db.blocked.has(req.user.email)) return res.status(403).json({ message: 'Usuario bloqueado' });
    next();
  } catch {
    res.status(401).json({ message: 'Token inválido' });
  }
}
function admin(req, res, next) {
  const u = db.users.find(x => x.id === req.user.id);
  if (!u || !u.is_admin) return res.status(403).json({ message: 'Solo admin' });
  next();
}
const pub = u => { const { password, ...r } = u; return r; };

// --- salud ---
app.get('/api/health', (req, res) => {
  res.json({ ok: true, users: db.users.length, alerts: db.alerts.length, time: new Date().toISOString() });
});

// --- auth ---
app.post('/api/register', (req, res) => {
  const { email, password, nombres, apellidos, grado, fuerza, especialidad } = req.body || {};
  if (!email || !password) return res.status(400).json({ message: 'Email y password requeridos' });
  if (db.users.some(u => u.email === email)) return res.status(409).json({ message: 'Email ya registrado' });

  const is_admin = db.users.length === 0; // 1er usuario = admin
  const user = { id: ++idCounter, email, password, nombres, apellidos, grado, fuerza, especialidad, is_admin };
  db.users.push(user);

  res.json({ user: pub(user), message: 'Registrado' });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const u = db.users.find(x => x.email === email && x.password === password);
  if (!u) return res.status(401).json({ message: 'Credenciales inválidas' });
  if (db.blocked.has(email)) return res.status(403).json({ message: 'Usuario bloqueado' });

  db.accessLog.push({ created_at: new Date().toISOString(), email, estado: 'OK' });

  // agente online
  if (!db.agents.find(a => a.email === email)) {
    db.agents.push({ email, rol: u.is_admin ? 'admin' : 'user', lat: null, lng: null, updated_at: new Date().toISOString() });
  }

  const token = jwt.sign({ id: u.id, email: u.email }, JWT_SECRET, { expiresIn: '2d' });
  res.json({ token, user: pub(u) });
});

app.get('/api/me', auth, (req, res) => {
  const u = db.users.find(x => x.id === req.user.id);
  if (!u) return res.status(404).json({ message: 'No encontrado' });
  res.json({ user: pub(u) });
});

// --- reports/alerts (solo manuales) ---
app.post('/api/reports', auth, (req, res) => {
  const b = req.body || {};
  const u = db.users.find(x => x.id === req.user.id);
  const item = {
    id: ++idCounter,
    created_at: new Date().toISOString(),
    usuario: u?.email || '',
    nivel: b.nivel || 'MEDIA',
    operacion: b.operacion || b.tipo || '',
    descripcion: b.descripcion || '',
    lat: b.lat ?? null,
    lng: b.lng ?? null,
    pais_ciudad: b.pais_ciudad || '',
    lugar_cod: b.lugar_cod || '',
    personalidad: b.personalidad || '',
    unidad_policial: b.unidad_policial || '',
    accion_oponente: b.accion_oponente || '',
    material_equipo: b.material_equipo || '',
    transporte: b.transporte || '',
    otros: b.otros || '',
    clasificacion_seg: b.clasificacion_seg || '',
    tipo_doc: b.tipo_doc || '',
    color_code: b.color_code || ''
  };
  db.alerts.unshift(item);
  res.json({ ok: true, item });
});

app.get('/api/admin/alerts', auth, (req, res) => {
  const limit = Math.max(1, Math.min(5000, parseInt(req.query.limit || '200', 10)));
  const items = db.alerts.slice(0, limit);
  res.json({ items });
});

// --- export CSV / PDF básico ---
app.get('/api/admin/alerts/export/csv', auth, (req, res) => {
  const date = req.query.date; // YYYY-MM-DD
  const filtered = db.alerts.filter(a => (a.created_at || '').startsWith(date));
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="reporte_${date}.csv"`);
  const cols = [
    'id','created_at','nivel','operacion','usuario','lat','lng',
    'pais_ciudad','lugar_cod','personalidad','unidad_policial','accion_oponente',
    'material_equipo','transporte','otros','clasificacion_seg','tipo_doc','color_code','descripcion'
  ];
  const s = stringify({ header: true, columns: cols });
  s.pipe(res);
  filtered.forEach(r => s.write(cols.reduce((o,k)=> (o[k]=r[k]??'', o), {})));
  s.end();
});

app.get('/api/admin/alerts/export/pdf', auth, (req, res) => {
  const date = req.query.date;
  const filtered = db.alerts.filter(a => (a.created_at || '').startsWith(date));
  const lines = filtered.map(a => `${a.created_at} | ${a.nivel} | ${a.operacion} | ${a.usuario} | ${a.lat??''},${a.lng??''} | ${a.pais_ciudad} | ${a.descripcion}`).join('\n');
  const content = `%PDF-1.4
1 0 obj<<>>endobj
2 0 obj<< /Length 3 0 R >>stream
BT /F1 12 Tf 50 750 Td (${escapePdf(lines || `Reporte ${date}`)}) Tj ET
endstream endobj
3 0 obj ${String((lines||'').length + 40)}
endobj
4 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj
5 0 obj<< /Type /Page /Parent 6 0 R /MediaBox [0 0 612 792] /Contents 2 0 R /Resources << /Font << /F1 4 0 R >> >> >>endobj
6 0 obj<< /Type /Pages /Kids [5 0 R] /Count 1 >>endobj
7 0 obj<< /Type /Catalog /Pages 6 0 R >>endobj
xref
0 8
0000000000 65535 f 
0000000010 00000 n 
0000000050 00000 n 
0000000000 00000 n 
0000000170 00000 n 
0000000250 00000 n 
0000000370 00000 n 
0000000440 00000 n 
trailer<< /Size 8 /Root 7 0 R >>
startxref
520
%%EOF`;
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="reporte_${date}.pdf"`);
  res.send(content);
});
function escapePdf(s=''){ return String(s).replace(/[()\\]/g, m => ({'(':'\\(',')':'\\)','\\':'\\\\'}[m])); }

// --- accesos (admin) ---
app.get('/api/admin/access', auth, admin, (req, res) => { res.json({ items: db.accessLog.slice(-200).reverse() }); });
app.post('/api/admin/access/block', auth, admin, (req, res) => {
  const { email } = req.body || {}; if (!email) return res.status(400).json({ message: 'email requerido' });
  db.blocked.add(email); db.accessLog.push({ created_at: new Date().toISOString(), email, estado: 'BLOQUEADO' }); res.json({ ok: true });
});
app.delete('/api/admin/access', auth, admin, (req, res) => {
  const { email } = req.body || {}; if (!email) return res.status(400).json({ message: 'email requerido' });
  db.blocked.delete(email); db.accessLog.push({ created_at: new Date().toISOString(), email, estado: 'ELIMINADO' }); res.json({ ok: true });
});

// --- agentes conectados (para mapa)
app.get('/api/admin/agents', auth, (req, res) => {
  res.json({ items: db.agents });
});

app.listen(PORT, () => console.log(`CIE-297 backend on :${PORT}`));

// server.js
const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

// ================== MEMORIA DEL SERVIDOR ==================
let users = [
  {
    id: 1,
    nombre: "Administrador",
    email: "admin@cie297.mil",
    password: "admin123",
    is_admin: true,
    grado: "WW",
    fuerza: "MA",
  },
];

let tokens = {};       // token -> userId
let alerts = [];       // alertas enviadas
let accesses = [];     // log de accesos
let agents = [];       // posiciones en el mapa

// ================== HEALTH CHECK ==================
app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

// ================== MIDDLEWARE AUTH ==================
function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const parts = header.split(" ");
  const token = parts.length === 2 ? parts[1] : "";

  if (!token || !tokens[token]) {
    return res.status(401).json({ message: "No autorizado" });
  }

  const user = users.find((u) => u.id === tokens[token]);
  if (!user) return res.status(401).json({ message: "No autorizado" });

  req.user = user;
  next();
}

function adminOnly(req, res, next) {
  if (!req.user || !req.user.is_admin) {
    return res.status(403).json({ message: "Solo administrador" });
  }
  next();
}

// ================== AUTH: REGISTER + LOGIN ==================
app.post("/api/register", (req, res) => {
  const { nombre, email, password, grado, fuerza } = req.body || {};

  if (!nombre || !email || !password) {
    return res.status(400).json({ message: "Faltan datos" });
  }

  const exists = users.some((u) => u.email === email);
  if (exists) return res.status(400).json({ message: "Email ya registrado" });

  const id = users.length ? users[users.length - 1].id + 1 : 1;
  const user = {
    id,
    nombre,
    email,
    password, // sin encriptar para simplificar
    grado: grado || "",
    fuerza: fuerza || "",
    is_admin: false,
  };
  users.push(user);

  return res.json({ ok: true });
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body || {};
  const user = users.find((u) => u.email === email && u.password === password);
  if (!user) {
    return res.status(401).json({ message: "Credenciales inválidas" });
  }

  const token = `${user.id}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  tokens[token] = user.id;

  return res.json({
    token,
    user: {
      email: user.email,
      nombre: user.nombre,
      is_admin: user.is_admin || false,
    },
  });
});

// ================== REPORTES ==================
app.post("/api/reports", auth, (req, res) => {
  const body = req.body || {};
  const now = body.fecha || Date.now();

  const report = {
    ...body,
    fecha: now,
    usuarioEmail: req.user.email,
  };

  alerts.push(report);
  return res.json({ ok: true });
});

// ------------------ LISTAR ALERTAS (usuario y admin) ------------------
app.get("/api/admin/alerts", auth, (req, res) => {
  let result = alerts;

  // si NO es admin, solo sus propias alertas
  if (!req.user.is_admin) {
    result = alerts.filter((a) => a.usuarioEmail === req.user.email);
  }

  // decoramos con objeto usuario (para tabla admin)
  const decorated = result.map((a) => ({
    ...a,
    usuario: { email: a.usuarioEmail || "-" },
  }));

  return res.json({ alertas: decorated });
});

// ================== ACCESOS ==================
app.post("/api/admin/access/log", auth, (req, res) => {
  const now = req.body?.fecha || Date.now();
  const ipHeader = req.headers["x-forwarded-for"];
  const ip =
    (ipHeader && ipHeader.split(",")[0]) ||
    req.ip ||
    "-";

  const item = {
    email: req.user.email,
    nombre: req.user.nombre || "",
    estado: req.body?.estado || "OK",
    fecha: now,
    ip,
  };

  accesses.push(item);
  return res.json({ ok: true });
});

app.get("/api/admin/access", auth, (req, res) => {
  let result = accesses;
  if (!req.user.is_admin) {
    result = accesses.filter((a) => a.email === req.user.email);
  }
  return res.json({ accesos: result });
});

app.post("/api/admin/access/block", auth, adminOnly, (req, res) => {
  const { email } = req.body || {};
  accesses = accesses.map((a) =>
    a.email === email ? { ...a, estado: "BLOQUEADO" } : a
  );
  return res.json({ ok: true });
});

app.delete("/api/admin/access", auth, adminOnly, (req, res) => {
  const { email } = req.body || {};
  accesses = accesses.filter((a) => a.email !== email);
  return res.json({ ok: true });
});

// ================== POSICIONES / MAPA ==================
app.post("/api/position", auth, (req, res) => {
  const { lat, lng, color } = req.body || {};
  if (typeof lat !== "number" || typeof lng !== "number") {
    return res.status(400).json({ message: "Lat/Lng inválidos" });
  }

  const existingIndex = agents.findIndex((a) => a.email === req.user.email);
  const agentData = {
    email: req.user.email,
    lat,
    lng,
    color: color || "VERDE",
  };

  if (existingIndex >= 0) {
    agents[existingIndex] = agentData;
  } else {
    agents.push(agentData);
  }

  return res.json({ ok: true });
});

app.get("/api/agents", auth, (req, res) => {
  return res.json({ agents });
});

// ================== DEFAULT ROOT ==================
app.get("/", (req, res) => {
  res.send("CIE-297 backend OK");
});

// ================== INICIO DEL SERVIDOR ==================
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`CIE-297 backend escuchando en puerto ${PORT}`);
});



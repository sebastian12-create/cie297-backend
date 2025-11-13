// server.js - CIE-297 BACKEND
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "super-secreto-largo-123";

app.use(
  cors({
    origin: true, // permite Vercel y otros orígenes
    credentials: true,
  })
);
app.use(express.json());

// ====== "Base de datos" simple en memoria ======
const users = [
  // usuario admin inicial
  {
    email: "admin@cie297.mil",
    nombre: "Administrador",
    password: "admin123", // cámbialo en producción
    grado: "WW",
    fuerza: "MA",
    is_admin: true,
  },
];

let reports = [];  // todas las alertas
let accesses = []; // todos los accesos
let agents = [];   // posiciones en el mapa

// ====== Helper de autenticación ======
function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const parts = header.split(" ");
  const token = parts.length === 2 ? parts[1] : null;
  if (!token) return res.status(401).json({ message: "Sin token" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { email, is_admin }
    next();
  } catch (err) {
    return res.status(401).json({ message: "Token inválido" });
  }
}

// ====== RUTAS DE USUARIO ======

// Registrar
app.post("/api/register", (req, res) => {
  const { nombre, email, password, grado, fuerza } = req.body || {};
  if (!nombre || !email || !password) {
    return res.status(400).json({ message: "Faltan datos" });
  }
  if (users.find((u) => u.email === email)) {
    return res.status(400).json({ message: "Ya existe ese usuario" });
  }
  const user = { nombre, email, password, grado, fuerza, is_admin: false };
  users.push(user);
  return res.json({ ok: true });
});

// Login
app.post("/api/login", (req, res) => {
  const { email, password } = req.body || {};
  const u = users.find((x) => x.email === email && x.password === password);
  if (!u) return res.status(401).json({ message: "Credenciales inválidas" });

  const token = jwt.sign(
    { email: u.email, is_admin: u.is_admin },
    JWT_SECRET,
    { expiresIn: "12h" }
  );

  const { password: _pw, ...userPublic } = u;
  return res.json({ token, user: userPublic });
});

// ====== POSICIONES EN EL MAPA ======

app.post("/api/position", auth, (req, res) => {
  const { lat, lng, color } = req.body || {};
  if (typeof lat !== "number" || typeof lng !== "number") {
    return res.status(400).json({ message: "Lat/Lng inválidos" });
  }

  const existingIndex = agents.findIndex((a) => a.email === req.user.email);
  const item = {
    email: req.user.email,
    lat,
    lng,
    color: (color || "VERDE").toUpperCase(),
    updated_at: Date.now(),
  };

  if (existingIndex >= 0) agents[existingIndex] = item;
  else agents.push(item);

  return res.json({ ok: true });
});

// Lista de agentes para el mapa
app.get("/api/agents", auth, (req, res) => {
  res.json({ agents });
});

// ====== ACCESOS ======

app.post("/api/admin/access/log", auth, (req, res) => {
  const { estado = "OK" } = req.body || {};
  const item = {
    email: req.user.email,
    nombre: req.body.nombre || "",
    ip: req.ip,
    estado,
    fecha: Date.now(),
  };
  accesses.push(item);
  return res.json({ ok: true });
});

// Ver accesos
app.get("/api/admin/access", auth, (req, res) => {
  const data = req.user.is_admin
    ? accesses
    : accesses.filter((a) => a.email === req.user.email);
  return res.json({ accesos: data });
});

// Bloquear un email
app.post("/api/admin/access/block", auth, (req, res) => {
  if (!req.user.is_admin)
    return res.status(403).json({ message: "Solo admin" });

  const { email } = req.body || {};
  accesses = accesses.map((a) =>
    a.email === email ? { ...a, estado: "BLOQUEADO" } : a
  );
  return res.json({ ok: true });
});

// Eliminar accesos de un email
app.delete("/api/admin/access", auth, (req, res) => {
  if (!req.user.is_admin)
    return res.status(403).json({ message: "Solo admin" });

  const { email } = req.body || {};
  accesses = accesses.filter((a) => a.email !== email);
  return res.json({ ok: true });
});

// ====== REPORTES / ALERTAS ======

// Crear reporte
app.post("/api/reports", auth, (req, res) => {
  const rep = {
    ...req.body,
    usuario: { email: req.user.email },
    fecha: req.body.fecha || Date.now(),
  };
  reports.push(rep);
  return res.json({ ok: true });
});

// Listar alertas (para admin y usuario)
app.get("/api/admin/alerts", auth, (req, res) => {
  let data;
  if (req.user.is_admin) {
    data = reports;
  } else {
    data = reports.filter(
      (r) => r.usuario && r.usuario.email === req.user.email
    );
  }
  const ordered = [...data].sort(
    (a, b) => (b.fecha || 0) - (a.fecha || 0)
  );
  return res.json({ alertas: ordered });
});

// ====== ROOT ======
app.get("/", (req, res) => {
  res.send("CIE-297 backend OK");
});

// ====== START ======
app.listen(PORT, () => {
  console.log("CIE-297 backend escuchando en puerto", PORT);
});



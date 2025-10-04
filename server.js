// server.js
import express from "express";
import fs from "fs";
import cors from "cors";
import bodyParser from "body-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import crypto from "crypto";

const app = express();
app.use(helmet());
app.use(cors());
app.use(bodyParser.json());

// Rate limiter básico
app.use(rateLimit({ windowMs: 60 * 1000, max: 120 }));

const PORT = process.env.PORT || 3000;
const DATA_FILE = "./licenses.json";
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "CAMBIA_ESTE_TOKEN"; // setea en Render

// Helpers
function ensureDataFile() {
  if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, "[]", "utf8");
}
function loadLicenses() {
  ensureDataFile();
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  } catch (e) {
    return [];
  }
}
function saveLicenses(arr) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(arr, null, 2), "utf8");
}
function generateKey() {
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  return crypto.randomBytes(16).toString("hex");
}

// RUTA: raíz
app.get("/", (req, res) => {
  res.send("🟢 API de licencias MTA funcionando");
});

// RUTA: crear licencia (protegida por ADMIN_TOKEN)
// Headers: x-admin-token: <token>
// Body JSON: { "dueño":"Didier", "ip":"123.45.67.89", "diasValidez":30, "key": optional }
app.post("/crear", (req, res) => {
  const token = req.headers["x-admin-token"] || req.body.adminToken;
  if (!token || token !== ADMIN_TOKEN) return res.status(401).json({ error: "No autorizado" });

  const { dueño = "desconocido", ip = null, diasValidez = null, key: providedKey = null } = req.body;

  const licencias = loadLicenses();

  // generar clave única o validar la proporcionada
  let key = providedKey || generateKey();
  if (licencias.find(l => l.key === key)) {
    // si la key proporcionada colisiona
    return res.status(400).json({ creada: false, error: "Clave ya existe" });
  }

  const now = Date.now();
  let expires = null;
  if (Number.isFinite(Number(diasValidez)) && Number(diasValidez) > 0) {
    expires = now + Number(diasValidez) * 24 * 60 * 60 * 1000;
  }

  const licenciaObj = {
    key,
    dueño,
    ip: ip || null,
    createdAt: now,
    expires,
    active: true,
    notas: ""
  };

  licencias.push(licenciaObj);
  saveLicenses(licencias);

  res.json({ creada: true, licencia: licenciaObj });
});

// RUTA: verificar licencia (POST recomendado)
// Body JSON: { "key": "xxx", "ip": "a.b.c.d" }
// Respuesta: { valida: true, dueño: "..."} o {valida:false, mensaje: "..."}
app.post("/verificar", (req, res) => {
  const { key, ip } = req.body || {};
  if (!key) return res.json({ valida: false, mensaje: "Falta key" });

  const licencias = loadLicenses();
  const lic = licencias.find(l => l.key === key);

  if (!lic) return res.json({ valida: false, mensaje: "Clave no encontrada" });
  if (!lic.active) return res.json({ valida: false, mensaje: "Licencia desactivada" });

  // expiración
  if (lic.expires && Date.now() > lic.expires) {
    lic.active = false;
    saveLicenses(licencias);
    return res.json({ valida: false, mensaje: "Licencia expirada" });
  }

  // Si la licencia no tiene IP asignada y recibimos ip, la vinculamos (opcional)
  const clientIp = ip || req.ip;
  if (!lic.ip && clientIp) {
    lic.ip = clientIp;
    saveLicenses(licencias);
  }

  // Si tiene IP y no coincide, rechazo
  if (lic.ip && clientIp && lic.ip !== clientIp) {
    return res.json({ valida: false, mensaje: "IP no autorizada", ip_autorizada: lic.ip, ip_actual: clientIp });
  }

  return res.json({ valida: true, dueño: lic.dueño });
});

// RUTA: listar licencias (solo admin) — opcional
app.get("/listar", (req, res) => {
  const token = req.headers["x-admin-token"] || req.query.adminToken;
  if (!token || token !== ADMIN_TOKEN) return res.status(401).json({ error: "No autorizado" });
  res.json(loadLicenses());
});

app.listen(PORT, () => console.log(`API de licencias corriendo en puerto ${PORT}`));

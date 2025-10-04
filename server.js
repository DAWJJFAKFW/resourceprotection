const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const fs = require("fs");

const app = express();
app.use(helmet());
app.use(express.json());

// Limita 60 peticiones por minuto por IP
app.use(rateLimit({ windowMs: 60000, max: 60 }));

// Archivo donde se guardan las licencias
const DB_FILE = "./licencias.json";
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, "{}");

function getLicencias() {
  return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}
function guardarLicencias(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// Verificar licencia
app.post("/api/verify", (req, res) => {
  const key = req.body.key;
  const ip = req.ip;

  if (!key) return res.status(400).json({ status: "error", message: "Falta clave" });

  const db = getLicencias();
  const lic = db[key];

  if (!lic || lic.activa === false)
    return res.json({ status: "invalida", motivo: "No existe o está desactivada" });

  if (lic.ip && lic.ip !== ip) {
    return res.json({ status: "ip_no_autorizada", ip_autorizada: lic.ip });
  }

  res.json({ status: "ok", dueño: lic.dueño });
});

// Crear nueva licencia (solo para ti)
app.post("/api/create", (req, res) => {
  const { key, dueño, ip } = req.body;
  if (!key || !dueño) return res.status(400).json({ error: "Faltan datos" });

  const db = getLicencias();
  db[key] = { dueño, ip: ip || null, activa: true };
  guardarLicencias(db);

  res.json({ creada: true, key, dueño, ip });
});

app.get("/", (req, res) => {
  res.send("API de licencias MTA corriendo correctamente ✅");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor iniciado en puerto ${PORT}`));

"use strict";
const express = require("express");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

/* ================= CONFIG ================= */
const CFG = {
  clientId: process.env.CLIENT_ID || "1565364176329904279",
  guildId: process.env.GUILD_ID || "1565369736856862831",
  reqRole: process.env.REQ_ROLE || "1565378109866508298", // San Andreas State Police
  staffRoles: (process.env.STAFF_ROLE_IDS || "").split(",").map(s => s.trim()).filter(Boolean),
  discordApi: process.env.DISCORD_API || "https://discord.com/api/v10",
  sessionHours: 6,
};
// Du grade le plus haut au plus bas : le premier rôle trouvé est utilisé
const GRADES = [
  ["Chief", "1565369851114029247"], ["Assistant Chief", "1565377027400536225"],
  ["Commandant", "1565377022166044692"], ["Capitaine", "1565376958844510329"],
  ["Lieutenant Chef", "1565369814283849749"], ["Lieutenant", "1565369766838018168"],
  ["Sergent Chef", "1565376798420631662"], ["Sergent III", "1565376440495640616"],
  ["Sergent II", "1565376432086196404"], ["Sergent I", "1565376419624919110"],
  ["Senior Lead Officier", "1565376408237375610"], ["Officier III", "1565376401702649917"],
  ["Officier II", "1565376413387718707"], ["Officier I", "1565376426260299836"],
  ["Cadet", "1565376436599128194"], ["Rookie", "1565369903681114235"],
];

/* ================= BASE DE DONNÉES ================= */
const dbPath = process.env.DB_PATH || path.join(__dirname, "data", "sasp.db");
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new Database(dbPath);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS tickets(
  user_id TEXT PRIMARY KEY, name TEXT NOT NULL, matricule TEXT NOT NULL UNIQUE,
  grade TEXT, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS reports(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL REFERENCES tickets(user_id) ON DELETE CASCADE,
  ref TEXT, data TEXT NOT NULL, text TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending', comment TEXT, reviewer TEXT,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS ix_reports_user ON reports(user_id);
CREATE TABLE IF NOT EXISTS sessions(
  hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL,
  grade TEXT, staff INTEGER NOT NULL, exp INTEGER NOT NULL);
`);

// Migration : nom/prénom et UUID demandés à la création du ticket
for (const col of ["full_name", "uuid"]) {
  if (!db.prepare("PRAGMA table_info(tickets)").all().some(c => c.name === col))
    db.exec(`ALTER TABLE tickets ADD COLUMN ${col} TEXT`);
}

/* ================= OUTILS ================= */
const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(express.json({ limit: "200kb" }));
app.use((req, res, next) => {
  res.set({
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Content-Security-Policy":
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
  });
  next();
});

const hits = new Map();
function limit(max, windowMs) {
  return (req, res, next) => {
    const k = req.ip + req.path, now = Date.now();
    const a = (hits.get(k) || []).filter(t => now - t < windowMs);
    if (a.length >= max) return res.status(429).json({ error: "trop_de_requetes" });
    a.push(now); hits.set(k, a); next();
  };
}
setInterval(() => {
  hits.clear();
  db.prepare("DELETE FROM sessions WHERE exp < ?").run(Date.now());
}, 10 * 60 * 1000).unref();

const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const clean = (s, n) => String(s == null ? "" : s).slice(0, n);

function auth(req, res, next) {
  const m = /^Bearer (.{20,200})$/.exec(req.get("Authorization") || "");
  if (!m) return res.status(401).json({ error: "non_connecte" });
  const s = db.prepare("SELECT * FROM sessions WHERE hash=?").get(sha(m[1]));
  if (!s || s.exp < Date.now()) return res.status(401).json({ error: "session_expiree" });
  req.user = { id: s.user_id, name: s.name, grade: s.grade, staff: !!s.staff, hash: s.hash, exp: s.exp };
  next();
}
const getTicket = id => db.prepare("SELECT * FROM tickets WHERE user_id=?").get(id) || null;
const me = u => ({ id: u.id, name: u.name, grade: u.grade, staff: u.staff });
const parseReport = r => ({ ...r, data: JSON.parse(r.data) });

/* ================= ROUTES ================= */
app.get("/api/config", (req, res) => res.json({ clientId: CFG.clientId }));

// Le navigateur envoie le token Discord ; le serveur vérifie lui-même membre + rôles auprès de Discord
app.post("/api/login", limit(20, 60000), async (req, res) => {
  const token = req.body && req.body.token;
  if (typeof token !== "string" || token.length < 10 || token.length > 300)
    return res.status(400).json({ error: "token_invalide" });
  let r;
  try {
    r = await fetch(`${CFG.discordApi}/users/@me/guilds/${CFG.guildId}/member`, {
      headers: { Authorization: "Bearer " + token },
    });
  } catch (e) { return res.status(502).json({ error: "discord_indisponible" }); }
  if (r.status === 404) return res.status(403).json({ error: "pas_sur_le_serveur" });
  if (!r.ok) return res.status(401).json({ error: "token_refuse" });
  const mb = await r.json();
  const roles = Array.isArray(mb.roles) ? mb.roles : [];
  if (!roles.includes(CFG.reqRole)) return res.status(403).json({ error: "role_manquant" });

  const g = GRADES.find(x => roles.includes(x[1]));
  const user = {
    id: String(mb.user.id),
    name: clean(mb.nick || mb.user.global_name || mb.user.username, 80),
    grade: g ? g[0] : null,
    staff: roles.some(x => CFG.staffRoles.includes(x)),
  };
  const session = crypto.randomBytes(32).toString("hex");
  const exp = Date.now() + CFG.sessionHours * 3600 * 1000;
  db.prepare("INSERT INTO sessions(hash,user_id,name,grade,staff,exp) VALUES(?,?,?,?,?,?)")
    .run(sha(session), user.id, user.name, user.grade, user.staff ? 1 : 0, exp);
  const t = getTicket(user.id);
  if (t) db.prepare("UPDATE tickets SET name=?, grade=? WHERE user_id=?").run(user.name, user.grade, user.id);
  res.json({ session, exp, me: user, ticket: getTicket(user.id) });
});

app.get("/api/me", auth, (req, res) => res.json({ me: me(req.user), exp: req.user.exp, ticket: getTicket(req.user.id) }));

app.post("/api/logout", auth, (req, res) => {
  db.prepare("DELETE FROM sessions WHERE hash=?").run(req.user.hash);
  res.json({ ok: true });
});

// Création du ticket : le matricule n'est demandé qu'UNE fois
app.post("/api/ticket", auth, (req, res) => {
  if (getTicket(req.user.id)) return res.status(409).json({ error: "ticket_existe" });
  const b = req.body || {};
  const mat = String(b.matricule || "").trim();
  const fullName = String(b.full_name || "").trim().replace(/\s+/g, " ");
  const uuid = String(b.uuid || "").trim();
  if (!/^\d{1,10}$/.test(mat)) return res.status(400).json({ error: "matricule_invalide" });
  if (fullName.length < 3 || fullName.length > 80 || !fullName.includes(" ")) return res.status(400).json({ error: "nom_invalide" });
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(uuid)) return res.status(400).json({ error: "uuid_invalide" });
  try {
    db.prepare("INSERT INTO tickets(user_id,name,matricule,grade,created_at,full_name,uuid) VALUES(?,?,?,?,?,?,?)")
      .run(req.user.id, req.user.name, mat, req.user.grade, Date.now(), fullName, uuid);
  } catch (e) { return res.status(409).json({ error: "matricule_utilise" }); }
  res.json({ ticket: getTicket(req.user.id) });
});

// Complétion d'un ancien ticket : nom/prénom + UUID, une seule fois (si absents)
app.put("/api/ticket", auth, (req, res) => {
  const t = getTicket(req.user.id);
  if (!t) return res.status(409).json({ error: "pas_de_ticket" });
  if (t.full_name && t.uuid) return res.status(409).json({ error: "ticket_existe" });
  const b = req.body || {};
  const fullName = String(b.full_name || "").trim().replace(/\s+/g, " ");
  const uuid = String(b.uuid || "").trim();
  if (fullName.length < 3 || fullName.length > 80 || !fullName.includes(" ")) return res.status(400).json({ error: "nom_invalide" });
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(uuid)) return res.status(400).json({ error: "uuid_invalide" });
  db.prepare("UPDATE tickets SET full_name=?, uuid=? WHERE user_id=?").run(fullName, uuid, req.user.id);
  res.json({ ticket: getTicket(req.user.id) });
});

// Liste des tickets : le staff voit tout, un agent voit uniquement le sien
app.get("/api/tickets", auth, (req, res) => {
  const base = `SELECT t.*,
    (SELECT COUNT(*) FROM reports r WHERE r.user_id=t.user_id AND r.status='pending') AS pending,
    (SELECT COUNT(*) FROM reports r WHERE r.user_id=t.user_id) AS total FROM tickets t`;
  const rows = req.user.staff
    ? db.prepare(base + " ORDER BY pending DESC, name COLLATE NOCASE").all()
    : db.prepare(base + " WHERE t.user_id=?").all(req.user.id);
  res.json({ tickets: rows });
});

app.patch("/api/tickets/:uid", auth, (req, res) => {
  if (!req.user.staff) return res.status(403).json({ error: "interdit" });
  const mat = String((req.body && req.body.matricule) || "").trim();
  if (!/^\d{1,10}$/.test(mat)) return res.status(400).json({ error: "matricule_invalide" });
  if (!getTicket(req.params.uid)) return res.status(404).json({ error: "introuvable" });
  try { db.prepare("UPDATE tickets SET matricule=? WHERE user_id=?").run(mat, req.params.uid); }
  catch (e) { return res.status(409).json({ error: "matricule_utilise" }); }
  res.json({ ticket: getTicket(req.params.uid) });
});

// Suppression d'un ticket (staff) : supprime aussi tous ses rapports (ON DELETE CASCADE)
app.delete("/api/tickets/:uid", auth, (req, res) => {
  if (!req.user.staff) return res.status(403).json({ error: "interdit" });
  if (!getTicket(req.params.uid)) return res.status(404).json({ error: "introuvable" });
  db.prepare("DELETE FROM tickets WHERE user_id=?").run(req.params.uid);
  res.json({ ok: true });
});

app.get("/api/tickets/:uid/reports", auth, (req, res) => {
  if (req.params.uid !== req.user.id && !req.user.staff) return res.status(403).json({ error: "interdit" });
  if (!getTicket(req.params.uid)) return res.status(404).json({ error: "introuvable" });
  const rows = db.prepare("SELECT * FROM reports WHERE user_id=? ORDER BY created_at DESC").all(req.params.uid);
  res.json({ reports: rows.map(parseReport) });
});

function readBody(req) {
  const b = req.body || {};
  const text = typeof b.text === "string" ? b.text : "";
  const data = b.data && typeof b.data === "object" ? JSON.stringify(b.data) : "";
  if (!text.trim() || text.length > 30000 || !data || data.length > 60000) return null;
  return { ref: clean(b.ref, 40), text, data };
}

app.post("/api/reports", auth, limit(60, 60000), (req, res) => {
  if (!getTicket(req.user.id)) return res.status(409).json({ error: "pas_de_ticket" });
  const b = readBody(req);
  if (!b) return res.status(400).json({ error: "rapport_invalide" });
  const now = Date.now();
  const info = db.prepare("INSERT INTO reports(user_id,ref,data,text,status,created_at,updated_at) VALUES(?,?,?,?, 'pending',?,?)")
    .run(req.user.id, b.ref, b.data, b.text, now, now);
  res.json({ id: info.lastInsertRowid });
});

function ownReport(req, res) {
  const r = db.prepare("SELECT * FROM reports WHERE id=?").get(req.params.id);
  if (!r) { res.status(404).json({ error: "introuvable" }); return null; }
  return r;
}

// Modifier un rapport : seulement le sien, et pas s'il est déjà validé. Repasse « en attente ».
app.put("/api/reports/:id", auth, (req, res) => {
  const r = ownReport(req, res); if (!r) return;
  if (r.user_id !== req.user.id) return res.status(403).json({ error: "interdit" });
  if (r.status === "approved") return res.status(409).json({ error: "deja_valide" });
  const b = readBody(req);
  if (!b) return res.status(400).json({ error: "rapport_invalide" });
  db.prepare("UPDATE reports SET ref=?,data=?,text=?,status='pending',comment=NULL,reviewer=NULL,updated_at=? WHERE id=?")
    .run(b.ref, b.data, b.text, Date.now(), r.id);
  res.json({ ok: true });
});

app.delete("/api/reports/:id", auth, (req, res) => {
  const r = ownReport(req, res); if (!r) return;
  const own = r.user_id === req.user.id;
  if (!req.user.staff && !(own && r.status !== "approved")) return res.status(403).json({ error: "interdit" });
  db.prepare("DELETE FROM reports WHERE id=?").run(r.id);
  res.json({ ok: true });
});

// Validation par le staff (jamais sur son propre rapport)
app.post("/api/reports/:id/review", auth, (req, res) => {
  if (!req.user.staff) return res.status(403).json({ error: "interdit" });
  const r = ownReport(req, res); if (!r) return;
  if (r.user_id === req.user.id) return res.status(403).json({ error: "pas_son_propre_rapport" });
  const st = req.body && req.body.status;
  if (st !== "approved" && st !== "rejected") return res.status(400).json({ error: "statut_invalide" });
  db.prepare("UPDATE reports SET status=?, comment=?, reviewer=?, updated_at=? WHERE id=?")
    .run(st, clean(req.body.comment, 500) || null, req.user.name, Date.now(), r.id);
  res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, "public")));
app.use("/api", (req, res) => res.status(404).json({ error: "introuvable" }));

if (require.main === module) {
  app.listen(process.env.PORT || 3000, () => {
    console.log("SASP tickets prêt sur le port " + (process.env.PORT || 3000));
    if (!CFG.staffRoles.length) console.log("⚠ STAFF_ROLE_IDS est vide : personne ne peut voir les tickets des autres.");
  });
}
module.exports = app;

// RED PHONE: shared server helpers for SecureOps.
// RED PHONE: session cookies, AES-256-GCM encryption at rest, Upstash Redis over REST, input validation.
import crypto from "node:crypto";

export const PREFIX = "secureops:";
const COOKIE = "so_session";
const TTL = 60 * 60 * 12;
const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

export function envMissing() {
  return ["UPSTASH_REDIS_REST_URL", "UPSTASH_REDIS_REST_TOKEN", "ADMIN_PASSWORD", "SESSION_SECRET", "DATA_KEY"]
    .filter(k => !process.env[k]);
}

export async function redis(...cmd) {
  const r = await fetch(process.env.UPSTASH_REDIS_REST_URL, {
    method: "POST",
    headers: { Authorization: `Bearer ${process.env.UPSTASH_REDIS_REST_TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify(cmd),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.error) throw new Error("Database error: " + (j.error || r.status));
  return j.result;
}

// RED PHONE: everything stored in Redis is encrypted with DATA_KEY
const dataKey = () => crypto.createHash("sha256").update(process.env.DATA_KEY).digest();
export function seal(obj) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", dataKey(), iv);
  const ct = Buffer.concat([c.update(JSON.stringify(obj), "utf8"), c.final()]);
  return [iv, c.getAuthTag(), ct].map(b => b.toString("base64")).join(".");
}
export function unseal(s) {
  if (!s) return null;
  const [iv, tag, ct] = s.split(".").map(x => Buffer.from(x, "base64"));
  const d = crypto.createDecipheriv("aes-256-gcm", dataKey(), iv);
  d.setAuthTag(tag);
  return JSON.parse(Buffer.concat([d.update(ct), d.final()]).toString("utf8"));
}

// RED PHONE: result keys are hashed so email addresses never appear in key names
export const resultKey = (email) =>
  PREFIX + "result:" + crypto.createHmac("sha256", process.env.DATA_KEY).update(email).digest("hex");

export const emailsOf = (e) => [e.email, ...(e.altEmails || [])].filter(Boolean);

export async function loadState() {
  const s = unseal(await redis("GET", PREFIX + "state")) || {};
  return { employees: s.employees || [], shifts: s.shifts || [] };
}
export async function saveState(s) {
  await redis("SET", PREFIX + "state", seal({ employees: s.employees, shifts: s.shifts }));
}
export async function fullState() {
  const s = await loadState();
  const emails = [...new Set(s.employees.flatMap(emailsOf))];
  const results = {};
  if (emails.length) {
    const vals = await redis("MGET", ...emails.map(resultKey));
    emails.forEach((e, i) => { if (vals[i]) results[e] = unseal(vals[i]); });
  }
  return { ...s, results, hibp: !!process.env.HIBP_API_KEY };
}

// RED PHONE: signed, HttpOnly, SameSite=Strict session cookie, 12 hour life
const sign = (v) => crypto.createHmac("sha256", process.env.SESSION_SECRET).update(v).digest("base64url");
export function makeSession(res) {
  const p = Buffer.from(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + TTL })).toString("base64url");
  res.setHeader("Set-Cookie", `${COOKIE}=${p}.${sign(p)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${TTL}`);
}
export function clearSession(res) {
  res.setHeader("Set-Cookie", `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
}
function readCookie(req, name) {
  for (const part of (req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}
function authed(req) {
  const t = readCookie(req, COOKIE);
  if (!t) return false;
  const [p, s] = t.split(".");
  if (!p || !s) return false;
  const good = sign(p);
  if (s.length !== good.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(good))) return false;
  try { return JSON.parse(Buffer.from(p, "base64url").toString()).exp > Date.now() / 1000; } catch { return false; }
}
export function passwordOk(pw) {
  const a = crypto.createHash("sha256").update(String(pw || "")).digest();
  const b = crypto.createHash("sha256").update(process.env.ADMIN_PASSWORD).digest();
  return crypto.timingSafeEqual(a, b);
}
export const clientIp = (req) => String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";

export function guard(req, res, method) {
  res.setHeader("Cache-Control", "no-store");
  const missing = envMissing();
  if (missing.length) { res.status(500).json({ error: "Server not configured. Missing: " + missing.join(", ") }); return false; }
  if (req.method !== method) { res.status(405).json({ error: "Method not allowed" }); return false; }
  if (method !== "GET") {
    const o = req.headers.origin;
    try { if (o && new URL(o).host !== req.headers.host) { res.status(403).json({ error: "Bad origin" }); return false; } }
    catch { res.status(403).json({ error: "Bad origin" }); return false; }
  }
  if (!authed(req)) { res.status(401).json({ error: "Sign in required" }); return false; }
  return true;
}

// RED PHONE: validation, nothing reaches storage without passing through these
const str = (v, max) => String(v ?? "").trim().slice(0, max);
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TIME = /^([01]\d|2[0-3]):[0-5]\d$/;

export function cleanEmployee(i) {
  const name = str(i.name, 80);
  if (!name) throw new Error("Name is required");
  const email = str(i.email, 254).toLowerCase();
  if (!EMAIL.test(email)) throw new Error("Work email is not valid");
  const alt = (Array.isArray(i.altEmails) ? i.altEmails : []).map(x => str(x, 254).toLowerCase()).filter(x => x && x !== email);
  for (const a of alt) if (!EMAIL.test(a)) throw new Error(`Not a valid email: ${a}`);
  return {
    id: UUID.test(i.id || "") ? i.id : crypto.randomUUID(),
    name,
    role: str(i.role, 80),
    dept: str(i.dept, 60),
    email,
    altEmails: [...new Set(alt)].slice(0, 10),
    admin: !!i.admin,
    systems: (Array.isArray(i.systems) ? i.systems : []).map(x => str(x, 60)).filter(Boolean).slice(0, 30),
    clearance: str(i.clearance, 10),
    status: i.status === "leave" ? "leave" : "active",
    startDate: /^\d{4}-\d{2}-\d{2}$/.test(i.startDate || "") ? i.startDate : "",
  };
}

export function cleanShift(i, employees) {
  if (!employees.some(e => e.id === i.employeeId)) throw new Error("Pick a person");
  if (!DAYS.includes(i.day)) throw new Error("Pick a day");
  if (!TIME.test(i.start || "") || !TIME.test(i.end || "")) throw new Error("Times must look like 09:00");
  return {
    id: UUID.test(i.id || "") ? i.id : crypto.randomUUID(),
    employeeId: i.employeeId,
    day: i.day,
    start: i.start,
    end: i.end,
    location: ["HQ", "Remote", "Field"].includes(i.location) ? i.location : "HQ",
    task: str(i.task, 60),
  };
}

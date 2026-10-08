// RED PHONE: password sign in with per-IP lockout (8 tries per 15 minutes)
import { envMissing, redis, passwordOk, makeSession, clientIp, PREFIX } from "../lib/core.js";

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });
  const missing = envMissing();
  if (missing.length) return res.status(500).json({ error: "Server not configured. Missing: " + missing.join(", ") });
  try {
    const k = PREFIX + "login:" + clientIp(req);
    const n = await redis("INCR", k);
    if (n === 1) await redis("EXPIRE", k, 900);
    if (n > 8) return res.status(429).json({ error: "Too many attempts. Try again in 15 minutes." });
    if (!passwordOk(req.body?.password)) return res.status(401).json({ error: "Wrong password" });
    await redis("DEL", k);
    makeSession(res);
    res.status(200).json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

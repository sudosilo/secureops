// RED PHONE: clears the session cookie
import { clearSession } from "../lib/core.js";

export default function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  clearSession(res);
  res.status(200).json({ ok: true });
}

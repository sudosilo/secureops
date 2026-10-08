// RED PHONE: returns people, shifts, and stored breach results
import { guard, fullState } from "../lib/core.js";

export default async function handler(req, res) {
  if (!guard(req, res, "GET")) return;
  try { res.status(200).json(await fullState()); }
  catch (err) { res.status(500).json({ error: err.message }); }
}

// RED PHONE: breach lookup for one email through the Have I Been Pwned v3 API
// RED PHONE: only emails already on someone's profile can be checked
import { guard, loadState, emailsOf, redis, resultKey, seal } from "../lib/core.js";

const decode = (s) => s.replace(/<[^>]*>/g, "").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">");

export default async function handler(req, res) {
  if (!guard(req, res, "POST")) return;
  if (!process.env.HIBP_API_KEY) return res.status(503).json({ error: "Breach lookups are not set up yet. HIBP_API_KEY is missing." });
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const s = await loadState();
    if (!s.employees.some(e => emailsOf(e).includes(email))) return res.status(404).json({ error: "That email is not on anyone's profile" });

    const r = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`, {
      headers: { "hibp-api-key": process.env.HIBP_API_KEY, "user-agent": "SecureOps" },
    });
    if (r.status === 429) return res.status(429).json({ error: "Rate limited", retryAfter: Number(r.headers.get("retry-after")) || 7 });
    if (r.status === 401) return res.status(502).json({ error: "The breach service rejected the API key" });

    let breaches = [];
    if (r.status === 200) {
      breaches = (await r.json()).map(b => ({
        name: b.Name, title: b.Title, domain: b.Domain, date: b.BreachDate, added: b.AddedDate,
        count: b.PwnCount, dataClasses: b.DataClasses || [], verified: !!b.IsVerified,
        description: decode(String(b.Description || "")).slice(0, 600),
      }));
    } else if (r.status !== 404) {
      return res.status(502).json({ error: `Breach service returned ${r.status}` });
    }

    const result = { checkedAt: new Date().toISOString(), breaches };
    await redis("SET", resultKey(email), seal(result));
    res.status(200).json({ email, result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

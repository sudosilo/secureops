// RED PHONE: add, edit, delete people and shifts
import { guard, loadState, saveState, fullState, cleanEmployee, cleanShift, redis, resultKey, emailsOf } from "../lib/core.js";

export default async function handler(req, res) {
  if (!guard(req, res, "POST")) return;
  try {
    const { kind, op, item, id } = req.body || {};
    const s = await loadState();

    if (kind === "employee" && op === "upsert") {
      const e = cleanEmployee(item || {});
      const prev = s.employees.find(x => x.id === e.id);
      const others = s.employees.filter(x => x.id !== e.id);
      const taken = new Set(others.flatMap(emailsOf));
      const clash = emailsOf(e).find(x => taken.has(x));
      if (clash) throw new Error(`${clash} already belongs to someone else`);
      s.employees = [...others, e];
      // RED PHONE: drop stored results for any email removed from the profile
      if (prev) for (const em of emailsOf(prev)) if (!emailsOf(e).includes(em)) await redis("DEL", resultKey(em));
    } else if (kind === "employee" && op === "delete") {
      const gone = s.employees.find(x => x.id === id);
      s.employees = s.employees.filter(x => x.id !== id);
      s.shifts = s.shifts.filter(x => x.employeeId !== id);
      if (gone) for (const em of emailsOf(gone)) await redis("DEL", resultKey(em));
    } else if (kind === "shift" && op === "upsert") {
      const sh = cleanShift(item || {}, s.employees);
      s.shifts = [...s.shifts.filter(x => x.id !== sh.id), sh];
    } else if (kind === "shift" && op === "delete") {
      s.shifts = s.shifts.filter(x => x.id !== id);
    } else {
      throw new Error("Unknown action");
    }

    await saveState(s);
    res.status(200).json(await fullState());
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
}

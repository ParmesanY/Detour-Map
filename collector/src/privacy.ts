// The client IP is used for exactly two things and never stored: Cloudflare derives the ISP (ASN) and region
// from it, and it becomes a day-long pseudonym for rate limiting and for counting distinct reporters.
// The pseudonym is an HMAC with a random salt of the day; the salt is deleted when the day is over, after
// which a pseudonym can't be tied back to an address even by someone holding the database.

export function utcDay(now: Date): string {
  return now.toISOString().slice(0, 10);
}

export function utcHour(now: Date): string {
  return now.toISOString().slice(0, 13);
}

export function addDays(day: string, delta: number): string {
  const d = new Date(`${day}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + delta);
  return utcDay(d);
}

function toHex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** The day's salt, created on first use. INSERT OR IGNORE keeps one salt even when two requests race. */
export async function dailySalt(db: D1Database, day: string): Promise<string> {
  const salt = toHex(crypto.getRandomValues(new Uint8Array(32)).buffer);
  const row = await db
    .prepare("INSERT INTO salts (day, salt) VALUES (?1, ?2) ON CONFLICT(day) DO UPDATE SET day = day RETURNING salt")
    .bind(day, salt)
    .first<{ salt: string }>();
  if (!row) {
    throw new Error("salt not stored");
  }
  return row.salt;
}

export async function pseudonym(salt: string, ip: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(salt), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(ip));
  return toHex(mac).slice(0, 32);
}

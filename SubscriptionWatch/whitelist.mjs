import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";

const resolver = new Resolver({ timeout: 1000, tries: 1 });
const cache = new Map();
const MAX_AGE = 90000;

export function isWhitelisted(rules, ip, now = Date.now()) {
  if (rules.ipWhitelist?.includes(ip)) return true;
  for (const entry of rules.ipWhitelist || []) {
    if (isIP(entry)) continue;
    const cached = cache.get(entry);
    if (cached?.until > now && cached.ips.has(ip)) return true;
  }
  return false;
}

export async function refreshDomain(domain, resolve = resolver) {
  if (isIP(domain)) return;
  const answers = await Promise.allSettled([
    resolve.resolve4(domain),
    resolve.resolve6(domain),
  ]);
  const ips = new Set();
  for (const answer of answers)
    if (answer.status === "fulfilled")
      for (const ip of answer.value)
        if (isIP(ip)) ips.add(ip);
  // A failed lookup must never retain an old allowlist result.
  cache.set(domain, { ips, until: Date.now() + MAX_AGE });
}

export async function refreshWhitelist(rules, resolve = resolver) {
  const domains = [...new Set((rules.ipWhitelist || []).filter((item) => !isIP(item)))];
  for (let i = 0; i < domains.length; i += 8)
    await Promise.all(domains.slice(i, i + 8).map((domain) => refreshDomain(domain, resolve)));
}

export async function refreshAllWhitelists(db) {
  const domains = new Set();
  for (const panel of db.prepare("SELECT rules FROM panels").all()) {
    for (const item of JSON.parse(panel.rules).ipWhitelist || [])
      if (!isIP(item)) domains.add(item);
  }
  await refreshWhitelist({ ipWhitelist: [...domains] });
}

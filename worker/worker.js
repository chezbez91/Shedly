// Shedly reminder service: a Cloudflare Worker with a KV binding named SHEDLY.
// It stores push subscriptions and reminder dates. Item names are stored only
// when the person has turned "Show item names" on.
//
// Secrets and variables (set in the Worker's Settings → Variables and secrets):
//   VAPID_PUBLIC   (secret or text)  the public key the app also uses
//   VAPID_PRIVATE  (secret)          the private key, never shared
//   VAPID_SUBJECT  (text, optional)  a contact URL or mailto: address

const ALLOWED_ORIGINS = ["https://chezbez91.github.io"];
const te = new TextEncoder();

// ---------- small helpers ----------
function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0],
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin"
  };
}
function json(body, status, headers) {
  return new Response(JSON.stringify(body), { status: status || 200, headers: Object.assign({ "Content-Type": "application/json" }, headers || {}) });
}
function clampInt(v, lo, hi, dflt) {
  const n = Math.trunc(Number(v));
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : dflt;
}
function b64uToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64u(buf) {
  const b = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function concat(...parts) {
  const total = parts.reduce((n, p) => n + p.byteLength, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(new Uint8Array(p), off); off += p.byteLength; }
  return out;
}
async function hkdf(salt, ikm, info, length) {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, length * 8);
  return new Uint8Array(bits);
}

// ---------- VAPID: sign a short-lived JWT with the app's private key ----------
async function vapidAuthorization(endpoint, env) {
  const aud = new URL(endpoint).origin;
  const header = bytesToB64u(te.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const claims = bytesToB64u(te.encode(JSON.stringify({
    aud,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: env.VAPID_SUBJECT || "https://chezbez91.github.io/Shedly/"
  })));
  const pub = b64uToBytes(env.VAPID_PUBLIC);
  const key = await crypto.subtle.importKey("jwk", {
    kty: "EC", crv: "P-256", d: env.VAPID_PRIVATE,
    x: bytesToB64u(pub.slice(1, 33)), y: bytesToB64u(pub.slice(33, 65)), ext: true
  }, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, te.encode(header + "." + claims));
  return "vapid t=" + header + "." + claims + "." + bytesToB64u(sig) + ", k=" + env.VAPID_PUBLIC;
}

// ---------- Web Push payload encryption (RFC 8291, aes128gcm) ----------
async function encryptPayload(keys, plaintext) {
  const uaPublic = b64uToBytes(keys.p256dh);
  const authSecret = b64uToBytes(keys.auth);
  const as = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey("raw", as.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ecdhSecret = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, as.privateKey, 256));
  const ikm = await hkdf(authSecret, ecdhSecret, concat(te.encode("WebPush: info\0"), uaPublic, asPublic), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, te.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, te.encode("Content-Encoding: nonce\0"), 12);
  const aesKey = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const padded = concat(plaintext, new Uint8Array([2])); // 0x02 marks the last (only) record
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, padded));
  const recordSize = new Uint8Array([0, 0, 16, 0]); // 4096, big-endian
  return concat(salt, recordSize, new Uint8Array([asPublic.length]), asPublic, cipher);
}

async function sendPush(sub, message, env) {
  const body = await encryptPayload(sub.keys, te.encode(JSON.stringify(message)));
  const res = await fetch(sub.endpoint, {
    method: "POST",
    headers: {
      "TTL": "86400",
      "Urgency": "normal",
      "Content-Encoding": "aes128gcm",
      "Content-Type": "application/octet-stream",
      "Authorization": await vapidAuthorization(sub.endpoint, env)
    },
    body
  });
  return res.status;
}

// ---------- time helpers (the device sends its UTC offset in minutes) ----------
function localParts(nowMs, tzMin) {
  const d = new Date(nowMs + tzMin * 60000);
  const y = d.getUTCFullYear(), m = d.getUTCMonth() + 1, day = d.getUTCDate();
  const date = y + "-" + String(m).padStart(2, "0") + "-" + String(day).padStart(2, "0");
  return { date, hour: d.getUTCHours(), dow: d.getUTCDay(), dom: day, ms: Date.UTC(y, m - 1, day) };
}
function daysUntil(localMs, dateStr) {
  const [y, m, d] = dateStr.split("-").map(Number);
  return Math.round((Date.UTC(y, m - 1, d) - localMs) / 86400000);
}

// ---------- which message, if any, is due for one subscriber right now ----------
function candidates(sub, p) {
  const out = [];
  const pr = sub.prefs || {};
  const sent = sub.sent || {};
  if (p.hour >= 21 || p.hour < 8) return out; // quiet hours
  const showNames = !!pr.names;

  if (pr.weekly && p.dow === 0 && p.hour >= 18 && p.hour < 21 && !sub.shedThisWeek && sent.weekly !== p.date)
    out.push({ key: "weekly", mark: p.date, prio: 1, msg: { title: "Shedly", body: "Your weekly review is ready.", tag: "weekly" } });

  if (pr.streak && p.dow === 0 && p.hour >= 15 && p.hour < 18 && (sub.streak || 0) >= 2 && !sub.shedThisWeek && sent.streak !== p.date)
    out.push({ key: "streak", mark: p.date, prio: 2, msg: { title: "Shedly", body: "Your " + sub.streak + "-week streak needs one shed this week.", tag: "streak" } });

  if (pr.deadline && p.hour >= 9 && p.hour < 12) {
    for (const r of sub.reminders || []) {
      if (!r.remind || !r.dueDay) continue;
      const n = daysUntil(p.ms, r.dueDay);
      if (n !== 7 && n !== 3 && n !== 1) continue;
      const key = "d" + r.id + "-" + n;
      if (sent[key]) continue;
      const when = n === 1 ? "tomorrow" : "in " + n + " days";
      const body = showNames && r.text ? r.text + " is due " + when + "." : "An item is due " + when + ".";
      out.push({ key, mark: p.date, prio: 0, msg: { title: "Shedly", body, tag: "d" + r.id } });
    }
  }

  if (pr.stale && p.dom === 1 && p.hour >= 10 && p.hour < 12 && (sub.staleCount || 0) > 0 && sent.stale !== p.date.slice(0, 7))
    out.push({ key: "stale", mark: p.date.slice(0, 7), prio: 3, msg: { title: "Shedly", body: "Some items have gone a month untouched.", tag: "stale" } });

  return out;
}

// ---------- scheduled run: at most one reminder per person per day ----------
async function runReminders(env, now) {
  let cursor;
  do {
    const page = await env.SHEDLY.list({ prefix: "sub:", cursor });
    for (const k of page.keys) {
      try {
        const sub = await env.SHEDLY.get(k.name, "json");
        if (!sub) continue;
        const p = localParts(now, sub.tz || 0);
        const picks = candidates(sub, p).sort(function (a, b) { return a.prio - b.prio; });
        if (!picks.length || sub.lastPush === p.date) continue;
        const pick = picks[0];
        const status = await sendPush(sub, pick.msg, env);
        if (status === 404 || status === 410) { await env.SHEDLY.delete(k.name); continue; } // unsubscribed in the browser
        sub.sent = Object.assign({}, sub.sent, { [pick.key]: pick.mark });
        sub.lastPush = p.date;
        await env.SHEDLY.put(k.name, JSON.stringify(sub));
      } catch (err) {
        console.log("reminder failed", err && err.message);
      }
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
}

// ---------- HTTP endpoints ----------
async function idFor(endpoint) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", te.encode(endpoint)));
  return "sub:" + Array.from(d.slice(0, 16)).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
}

async function subscribe(body, env, headers) {
  const s = body.subscription || {};
  if (!s.endpoint || !/^https:\/\//.test(s.endpoint) || !s.keys || !s.keys.p256dh || !s.keys.auth)
    return json({ error: "bad subscription" }, 400, headers);
  const id = await idFor(s.endpoint);
  const old = (await env.SHEDLY.get(id, "json")) || {};
  const pr = body.prefs || {};
  const record = {
    endpoint: s.endpoint,
    keys: { p256dh: String(s.keys.p256dh), auth: String(s.keys.auth) },
    tz: clampInt(body.tz, -840, 840, 0),
    prefs: { weekly: !!pr.weekly, deadline: !!pr.deadline, stale: !!pr.stale, streak: !!pr.streak, names: !!pr.names },
    streak: clampInt(body.streak, 0, 9999, 0),
    shedThisWeek: !!body.shedThisWeek,
    staleCount: clampInt(body.staleCount, 0, 9999, 0),
    reminders: (Array.isArray(body.reminders) ? body.reminders : []).slice(0, 200).map(function (r) {
      return {
        id: String(r.id).slice(0, 40),
        dueDay: /^\d{4}-\d{2}-\d{2}$/.test(r.dueDay) ? r.dueDay : null,
        remind: !!r.remind,
        text: pr.names && r.text ? String(r.text).slice(0, 60) : ""
      };
    }),
    sent: old.sent || {},
    lastPush: old.lastPush || null,
    updated: Date.now()
  };
  await env.SHEDLY.put(id, JSON.stringify(record));
  return json({ ok: true }, 200, headers);
}

async function unsubscribe(body, env, headers) {
  if (!body.endpoint) return json({ error: "no endpoint" }, 400, headers);
  await env.SHEDLY.delete(await idFor(body.endpoint));
  return json({ ok: true }, 200, headers);
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const headers = corsHeaders(origin);
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/")
      return new Response("Shedly reminders are running.", { headers: { "Content-Type": "text/plain" } });
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });
    if (!ALLOWED_ORIGINS.includes(origin)) return json({ error: "origin not allowed" }, 403, headers);
    if (request.method !== "POST") return json({ error: "method not allowed" }, 405, headers);
    let body;
    try { body = await request.json(); } catch (e) { return json({ error: "bad json" }, 400, headers); }
    if (url.pathname === "/subscribe") return subscribe(body, env, headers);
    if (url.pathname === "/unsubscribe") return unsubscribe(body, env, headers);
    return json({ error: "not found" }, 404, headers);
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runReminders(env, Date.now()));
  }
};

// Exported for local tests only.
export { encryptPayload, vapidAuthorization, candidates, localParts, daysUntil };

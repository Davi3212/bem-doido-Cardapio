import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { getStore } from "@netlify/blobs";

export const analyticsStore = () => getStore("bem-doido-analytics");
export const securityStore = () => getStore("bem-doido-security");

export function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "cache-control": "no-store",
      "access-control-allow-origin": "*"
    }
  });
}

export function hash(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

export function maskIp(ip = "") {
  if(ip.includes(":")) {
    const parts = ip.split(":").filter(Boolean);
    return parts.slice(0, 3).join(":") + ":****";
  }
  const parts = ip.split(".");
  if(parts.length === 4) return `${parts[0]}.${parts[1]}.XX.XX`;
  return "oculto";
}

export async function getPasswordHash() {
  const store = securityStore();
  let passwordHash = await store.get("admin-password-hash", { type: "text", consistency: "strong" });
  if(!passwordHash) {
    const initial = process.env.ADMIN_INITIAL_PASSWORD;
    if(!initial) throw new Error("ADMIN_INITIAL_PASSWORD não configurada");
    passwordHash = hash(initial);
    await store.set("admin-password-hash", passwordHash);
  }
  return passwordHash;
}

export function makeToken(passwordHash) {
  const payload = {
    exp: Date.now() + 2 * 60 * 60 * 1000,
    nonce: crypto.randomUUID()
  };
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = createHmac("sha256", passwordHash).update(encoded).digest("base64url");
  return `${encoded}.${signature}`;
}

export async function verifyToken(req) {
  const auth = req.headers.get("authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const [encoded, signature] = token.split(".");
  if(!encoded || !signature) return false;
  const passwordHash = await getPasswordHash();
  const expected = createHmac("sha256", passwordHash).update(encoded).digest("base64url");
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if(a.length !== b.length || !timingSafeEqual(a, b)) return false;
  const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  return payload.exp > Date.now();
}

export function deviceFromUa(ua = "") {
  if(/android/i.test(ua)) return "Android";
  if(/iphone|ipad/i.test(ua)) return "iPhone/iPad";
  if(/windows/i.test(ua)) return "Windows";
  if(/macintosh|mac os/i.test(ua)) return "Mac";
  return "Outro aparelho";
}

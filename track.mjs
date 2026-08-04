import { analyticsStore, json, hash, maskIp, deviceFromUa } from "./_common.mjs";

const allowedTypes = new Set([
  "page_view","category_view","add_to_cart","cart_open",
  "whatsapp_order","promo_view"
]);

export default async (req, context) => {
  if(req.method !== "POST") return json({message:"Método não permitido"}, 405);
  let body;
  try { body = await req.json(); } catch { return json({message:"JSON inválido"}, 400); }
  if(!allowedTypes.has(body.type)) return json({message:"Evento inválido"}, 400);

  const timestamp = new Date().toISOString();
  const ip = context.ip || "";
  const event = {
    type: body.type,
    timestamp,
    sessionHash: hash(`${body.sessionId || "anon"}:${ip}`).slice(0, 20),
    ipMasked: maskIp(ip),
    device: deviceFromUa(req.headers.get("user-agent") || ""),
    country: context.geo?.country?.code || "",
    city: context.geo?.city || "",
    details: body.details && typeof body.details === "object" ? body.details : {},
    path: String(body.path || "").slice(0, 200)
  };
  const key = `${timestamp.slice(0,10)}/${Date.now()}-${crypto.randomUUID()}`;
  await analyticsStore().setJSON(key, event);
  return json({ok:true}, 202);
};

export const config = {
  path: "/api/track",
  method: "POST",
  rateLimit: { action:"rate_limit", aggregateBy:"ip", windowSize:60, windowLimit:120 }
};

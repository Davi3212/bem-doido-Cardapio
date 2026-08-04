import { analyticsStore, securityStore, json, hash, maskIp, deviceFromUa, getPasswordHash, makeToken } from "./_common.mjs";

export default async (req, context) => {
  if(req.method !== "POST") return json({message:"Método não permitido"}, 405);
  const ip = context.ip || "";
  const attemptKey = `attempts/${hash(ip).slice(0,24)}`;
  const security = securityStore();
  const state = await security.get(attemptKey, {type:"json", consistency:"strong"}) || {count:0, blockedUntil:0};
  if(state.blockedUntil > Date.now()) {
    return json({message:"Muitas tentativas. Aguarde 15 minutos."}, 429);
  }

  let body;
  try { body = await req.json(); } catch { return json({message:"JSON inválido"}, 400); }
  const passwordHash = await getPasswordHash();
  const success = hash(body.password || "") === passwordHash;
  const timestamp = new Date().toISOString();
  await analyticsStore().setJSON(
    `${timestamp.slice(0,10)}/${Date.now()}-${crypto.randomUUID()}`,
    {
      type: success ? "admin_login_success" : "admin_login_failed",
      timestamp,
      sessionHash: hash(ip).slice(0,20),
      ipMasked: maskIp(ip),
      device: deviceFromUa(req.headers.get("user-agent") || ""),
      country: context.geo?.country?.code || "",
      city: context.geo?.city || "",
      details: {}
    }
  );

  if(!success) {
    const count = (state.count || 0) + 1;
    const blockedUntil = count >= 5 ? Date.now() + 15 * 60 * 1000 : 0;
    await security.setJSON(attemptKey, {count: blockedUntil ? 0 : count, blockedUntil});
    return json({message: blockedUntil ? "Bloqueado por 15 minutos após 5 erros." : "Senha incorreta."}, 401);
  }

  await security.delete(attemptKey);
  return json({token: makeToken(passwordHash)});
};

export const config = {
  path: "/api/admin-login",
  method: "POST",
  rateLimit: { action:"rate_limit", aggregateBy:"ip", windowSize:60, windowLimit:20 }
};

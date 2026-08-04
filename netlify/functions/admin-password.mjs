import { securityStore, json, hash, getPasswordHash, makeToken, verifyToken } from "./_common.mjs";

export default async (req) => {
  if(!(await verifyToken(req))) return json({message:"Sessão inválida"}, 401);
  let body;
  try { body = await req.json(); } catch { return json({message:"JSON inválido"}, 400); }
  const currentHash = await getPasswordHash();
  if(hash(body.currentPassword || "") !== currentHash) return json({message:"Senha atual incorreta"}, 401);
  const next = String(body.newPassword || "");
  if(next.length < 6) return json({message:"A nova senha precisa ter 6 caracteres ou mais"}, 400);
  const nextHash = hash(next);
  await securityStore().set("admin-password-hash", nextHash);
  return json({ok:true, token:makeToken(nextHash)});
};

export const config = {
  path: "/api/admin-password",
  method: "POST",
  rateLimit: { action:"rate_limit", aggregateBy:"ip", windowSize:60, windowLimit:10 }
};

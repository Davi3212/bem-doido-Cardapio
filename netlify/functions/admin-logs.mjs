import { analyticsStore, json, verifyToken } from "./_common.mjs";

export default async (req) => {
  if(!(await verifyToken(req))) return json({message:"Sessão inválida"}, 401);
  const limit = Math.min(Number(new URL(req.url).searchParams.get("limit") || 200), 500);
  const store = analyticsStore();
  const entries = [];
  for await (const page of store.list({paginate:true})) {
    for(const blob of page.blobs) entries.push(blob.key);
  }
  entries.sort().reverse();
  const events = [];
  for(const key of entries.slice(0, limit)) {
    const item = await store.get(key, {type:"json"});
    if(item) events.push(item);
  }
  const visitorSet = new Set(events.filter(e => e.type === "page_view").map(e => e.sessionHash));
  const summary = {
    uniqueVisitors: visitorSet.size,
    pageViews: events.filter(e => e.type === "page_view").length,
    cartClicks: events.filter(e => e.type === "cart_open").length,
    failedLogins: events.filter(e => e.type === "admin_login_failed").length
  };
  return json({summary, events});
};

export const config = {
  path: "/api/admin-logs",
  method: "GET",
  rateLimit: { action:"rate_limit", aggregateBy:"ip", windowSize:60, windowLimit:30 }
};

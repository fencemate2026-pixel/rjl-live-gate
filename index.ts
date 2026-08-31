// RJL — authenticated open. The browser NEVER holds the HMAC secret or broker creds.
//   1. Caller must be a logged-in Supabase user (JWT in Authorization header).
//   2. User must be linked to the gate in gate_users.
//   3. Gate must not be suspended.
//   4. Function signs + publishes the open command server-side.
//
// Deploy:  supabase functions deploy gate-open      (keep JWT verification ON)

import { createClient } from "npm:@supabase/supabase-js@2";
import { admin, cors, getGateSecret, hmacHex, json, mqttPublish } from "../_shared/util.ts";

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  const authHeader = req.headers.get("Authorization");
  if (!authHeader) return json({ error: "unauthorized" }, 401);

  // Identify the caller from their JWT.
  const userClient = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_ANON_KEY")!,
    { global: { headers: { Authorization: authHeader } }, auth: { persistSession: false } },
  );
  const { data: { user } } = await userClient.auth.getUser();
  if (!user) return json({ error: "unauthorized" }, 401);

  let gateId = "";
  try { gateId = (await req.json()).gate_id; } catch { /* ignore */ }
  if (!gateId) return json({ error: "gate_id required" }, 400);

  const db = admin();

  // Is this user allowed on this gate?
  const { data: link } = await db.from("gate_users")
    .select("gate_id").eq("gate_id", gateId).eq("user_id", user.id).maybeSingle();
  if (!link) return json({ error: "forbidden" }, 403);

  // Suspended gates can't be opened from the app.
  const { data: gate } = await db.from("gates")
    .select("service_status").eq("id", gateId).maybeSingle();
  if (!gate) return json({ error: "gate not found" }, 404);
  if (gate.service_status === "suspended") return json({ error: "service suspended" }, 402);

  const secret = await getGateSecret(db, gateId);
  if (!secret) return json({ error: "gate not provisioned" }, 500);

  const ts = Date.now();
  const sig = await hmacHex(secret, `open|${gateId}|${ts}`);
  try {
    await mqttPublish(`rjl/gate/${gateId}/cmd`, JSON.stringify({ cmd: "open", ts, sig }), false);
  } catch (e) {
    return json({ error: "publish failed", detail: (e as Error).message }, 502);
  }
  return json({ ok: true, gate: gateId });
});

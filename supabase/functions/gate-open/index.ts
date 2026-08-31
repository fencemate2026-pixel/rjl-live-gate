// RJL — authenticated open. The browser NEVER holds the HMAC secret or broker creds.
// Deploy: supabase functions deploy gate-open
import { admin, cors, getGateSecret, json, publishOpen, userClient } from "../_shared/util.ts";

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  const authHeader = req.headers.get("Authorization");
  if (!authHeader) return json({ error: "unauthorized" }, 401);

  const { data: { user }, error: authError } = await userClient(authHeader).auth.getUser();
  if (authError || !user) return json({ error: "unauthorized" }, 401);

  let gateId = "";
  try {
    gateId = (await req.json()).gate_id ?? "";
  } catch {
    // ignore malformed body
  }
  if (!gateId) return json({ error: "gate_id required" }, 400);

  const db = admin();

  const { data: link, error: linkError } = await db.from("gate_users")
    .select("id")
    .eq("gate_id", gateId)
    .eq("user_id", user.id)
    .maybeSingle();
  if (linkError) return json({ error: "authorization lookup failed", detail: linkError.message }, 500);
  if (!link) return json({ error: "forbidden" }, 403);

  const { data: gate, error: gateError } = await db.from("gates")
    .select("service_status")
    .eq("id", gateId)
    .maybeSingle();
  if (gateError) return json({ error: "gate lookup failed", detail: gateError.message }, 500);
  if (!gate) return json({ error: "gate not found" }, 404);
  if (gate.service_status === "suspended") return json({ error: "service suspended" }, 402);

  const secret = await getGateSecret(db, gateId);
  if (!secret) return json({ error: "gate not provisioned" }, 500);

  try {
    await publishOpen(gateId, secret);
  } catch (e) {
    return json({ error: "publish failed", detail: (e as Error).message }, 502);
  }

  return json({ ok: true, gate: gateId });
});

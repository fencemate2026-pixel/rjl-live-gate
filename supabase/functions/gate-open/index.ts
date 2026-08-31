// RJL — authenticated open. The browser NEVER holds the HMAC secret or broker creds.
// Deploy: supabase functions deploy gate-open
import { admin, corsHeaders, getGateSecret, json, logGateAction, publishOpen, userClient } from "../_shared/util.ts";

Deno.serve(async (req) => {
  const origin = req.headers.get("origin");
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders(origin) });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405, origin);

  const authHeader = req.headers.get("Authorization");
  if (!authHeader) return json({ error: "unauthorized" }, 401, origin);

  const { data: { user }, error: authError } = await userClient(authHeader).auth.getUser();
  if (authError || !user) return json({ error: "unauthorized" }, 401, origin);

  let gateId = "";
  try {
    gateId = (await req.json()).gate_id ?? "";
  } catch {
    // ignore malformed body
  }
  if (!gateId) return json({ error: "gate_id required" }, 400, origin);

  const db = admin();

  const { data: link, error: linkError } = await db.from("gate_users")
    .select("id")
    .eq("gate_id", gateId)
    .eq("user_id", user.id)
    .maybeSingle();
  if (linkError) {
    console.error("authorization lookup failed", linkError);
    await logGateAction(db, {
      gateId,
      actionType: "open_request",
      actionStatus: "error",
      actionSource: "gate-open",
      actorUserId: user.id,
    }).catch((e) => console.error("audit log failed", e));
    return json({ error: "authorization lookup failed" }, 500, origin);
  }
  if (!link) {
    await logGateAction(db, {
      gateId,
      actionType: "open_request",
      actionStatus: "rejected",
      actionSource: "gate-open",
      actorUserId: user.id,
      detail: { reason: "user_not_linked" },
    }).catch((e) => console.error("audit log failed", e));
    return json({ error: "forbidden" }, 403, origin);
  }

  const { data: gate, error: gateError } = await db.from("gates")
    .select("service_status")
    .eq("id", gateId)
    .maybeSingle();
  if (gateError) {
    console.error("gate lookup failed", gateError);
    await logGateAction(db, {
      gateId,
      actionType: "open_request",
      actionStatus: "error",
      actionSource: "gate-open",
      actorUserId: user.id,
    }).catch((e) => console.error("audit log failed", e));
    return json({ error: "gate lookup failed" }, 500, origin);
  }
  if (!gate) {
    await logGateAction(db, {
      gateId,
      actionType: "open_request",
      actionStatus: "rejected",
      actionSource: "gate-open",
      actorUserId: user.id,
      detail: { reason: "gate_not_found" },
    }).catch((e) => console.error("audit log failed", e));
    return json({ error: "gate not found" }, 404, origin);
  }
  if (gate.service_status === "suspended") {
    await logGateAction(db, {
      gateId,
      actionType: "open_request",
      actionStatus: "rejected",
      actionSource: "gate-open",
      actorUserId: user.id,
      detail: { reason: "service_suspended" },
    }).catch((e) => console.error("audit log failed", e));
    return json({ error: "service suspended" }, 402, origin);
  }

  const secret = await getGateSecret(db, gateId);
  if (!secret) {
    await logGateAction(db, {
      gateId,
      actionType: "open_request",
      actionStatus: "error",
      actionSource: "gate-open",
      actorUserId: user.id,
      detail: { reason: "missing_gate_secret" },
    }).catch((e) => console.error("audit log failed", e));
    return json({ error: "gate not provisioned" }, 500, origin);
  }

  try {
    await publishOpen(gateId, secret);
  } catch (e) {
    console.error("publish failed", e);
    await logGateAction(db, {
      gateId,
      actionType: "open_publish",
      actionStatus: "error",
      actionSource: "gate-open",
      actorUserId: user.id,
    }).catch((err) => console.error("audit log failed", err));
    return json({ error: "publish failed" }, 502, origin);
  }

  await logGateAction(db, {
    gateId,
    actionType: "open_publish",
    actionStatus: "success",
    actionSource: "gate-open",
    actorUserId: user.id,
  }).catch((e) => console.error("audit log failed", e));

  return json({ ok: true, gate: gateId }, 200, origin);
});

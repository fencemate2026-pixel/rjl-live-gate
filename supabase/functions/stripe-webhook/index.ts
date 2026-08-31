// RJL — Stripe webhook for maintenance suspend/resume.
// Deploy: supabase functions deploy stripe-webhook --no-verify-jwt
import {
  admin,
  cors,
  getGateSecret,
  json,
  publishHold,
  requiredSetting,
  timingSafeEqual,
  updateGateServiceStatus,
} from "../_shared/util.ts";

type EventObject = Record<string, unknown>;

function asRecord(value: unknown): EventObject | null {
  return value !== null && typeof value === "object" ? value as EventObject : null;
}

function maybeString(value: unknown): string | null {
  if (typeof value === "string" && value.length > 0) return value;
  const rec = asRecord(value);
  if (rec && typeof rec.id === "string" && rec.id.length > 0) return rec.id;
  return null;
}

async function verifyStripeSignature(body: string, signatureHeader: string): Promise<boolean> {
  const secret = requiredSetting("STRIPE_WEBHOOK_SECRET");
  const parts = signatureHeader.split(",").map((part) => part.trim());
  const timestamp = parts.find((part) => part.startsWith("t="))?.slice(2);
  const signatures = parts.filter((part) => part.startsWith("v1=")).map((part) => part.slice(3));
  if (!timestamp || signatures.length === 0) return false;

  const age = Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp));
  if (!Number.isFinite(age) || age > 300) return false;

  const signedPayload = `${timestamp}.${body}`;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const raw = await crypto.subtle.sign("HMAC", key, enc.encode(signedPayload));
  const expected = [...new Uint8Array(raw)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return signatures.some((sig) => timingSafeEqual(sig, expected));
}

function deriveAction(eventType: string, object: EventObject):
  | { subscriptionId: string; hold: "on" | "off"; serviceStatus: "active" | "suspended"; reason: string }
  | null {
  if (eventType === "invoice.paid" || eventType === "invoice.payment_succeeded") {
    const subscriptionId = maybeString(object.subscription);
    if (!subscriptionId) return null;
    return { subscriptionId, hold: "off", serviceStatus: "active", reason: "invoice paid" };
  }

  if (eventType === "customer.subscription.updated" || eventType === "customer.subscription.deleted") {
    const subscriptionId = maybeString(object.id);
    const status = maybeString(object.status);
    if (!subscriptionId || !status) return null;
    if (status === "unpaid" || status === "canceled") {
      return { subscriptionId, hold: "on", serviceStatus: "suspended", reason: `subscription ${status}` };
    }
    if (status === "active" || status === "trialing") {
      return { subscriptionId, hold: "off", serviceStatus: "active", reason: `subscription ${status}` };
    }
  }

  return null;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  const signatureHeader = req.headers.get("stripe-signature");
  if (!signatureHeader) return json({ error: "missing stripe-signature" }, 400);

  const body = await req.text();
  const valid = await verifyStripeSignature(body, signatureHeader);
  if (!valid) return json({ error: "invalid stripe signature" }, 400);

  let event: EventObject;
  try {
    event = JSON.parse(body);
  } catch {
    return json({ error: "invalid json" }, 400);
  }

  const eventType = maybeString(event.type);
  const object = asRecord(asRecord(event.data)?.object);
  if (!eventType || !object) return json({ error: "invalid event payload" }, 400);

  const action = deriveAction(eventType, object);
  if (!action) {
    return json({ ok: true, ignored: true, event_type: eventType });
  }

  const db = admin();
  const { data: gate, error: gateLookupError } = await db.from("gates")
    .select("id, service_status, plan")
    .eq("stripe_subscription_id", action.subscriptionId)
    .maybeSingle();
  if (gateLookupError) return json({ error: "gate lookup failed", detail: gateLookupError.message }, 500);
  if (!gate) return json({ ok: true, ignored: true, reason: "subscription not linked to gate" });
  if (gate.plan !== "maintenance") {
    return json({ ok: true, ignored: true, reason: "gate is not on maintenance plan" });
  }

  const secret = await getGateSecret(db, gate.id);
  if (!secret) return json({ error: "gate secret missing" }, 500);

  try {
    await publishHold(gate.id, secret, action.hold);
    await updateGateServiceStatus(db, gate.id, action.serviceStatus);
  } catch (e) {
    return json({ error: "failed to sync gate state", detail: (e as Error).message }, 502);
  }

  return json({
    ok: true,
    gate: gate.id,
    service_status: action.serviceStatus,
    hold: action.hold,
    reason: action.reason,
  });
});

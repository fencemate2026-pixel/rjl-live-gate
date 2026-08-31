// Shared helpers for RJL gate Edge Functions.
import { createClient } from "npm:@supabase/supabase-js@2";

export function corsHeaders(origin: string | null = null): Record<string, string> {
  const headers: Record<string, string> = {
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, stripe-signature",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
  const allowedOrigins = (Deno.env.get("ALLOWED_ORIGINS") ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  if (origin && allowedOrigins.includes(origin)) headers["Access-Control-Allow-Origin"] = origin;
  return headers;
}

export function json(body: unknown, status = 200, origin: string | null = null) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders(origin), "content-type": "application/json" },
  });
}

export function requiredEnv(name: string): string {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`Missing required env: ${name}`);
  return value;
}

// Service-role client — bypasses RLS, used to read per-gate secrets and update service state.
export const admin = () =>
  createClient(
    requiredEnv("SUPABASE_URL"),
    requiredEnv("SUPABASE_SERVICE_ROLE_KEY"),
    { auth: { persistSession: false } },
  );

export const userClient = (authHeader: string) =>
  createClient(
    requiredEnv("SUPABASE_URL"),
    requiredEnv("SUPABASE_ANON_KEY"),
    { global: { headers: { Authorization: authHeader } }, auth: { persistSession: false } },
  );

// HMAC-SHA256 -> lowercase hex.
export async function hmacHex(secret: string, msg: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function timingSafeEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const aBytes = enc.encode(a);
  const bBytes = enc.encode(b);
  let diff = 0;
  const max = Math.max(aBytes.length, bBytes.length);
  diff |= aBytes.length !== bBytes.length ? 1 : 0;
  for (let i = 0; i < max; i++) {
    const av = i < aBytes.length ? aBytes[i] : 0x00;
    const bv = i < bBytes.length ? bBytes[i] : 0x00;
    diff |= av ^ bv;
  }
  return diff === 0;
}

// Connect to HiveMQ over WSS, publish once, disconnect.
export async function mqttPublish(topic: string, payload: string, retain = false): Promise<void> {
  const mqtt = (await import("npm:mqtt@5")).default;
  const url = `wss://${requiredEnv("HIVEMQ_HOST")}:8884/mqtt`;
  const client = mqtt.connect(url, {
    username: requiredEnv("HIVEMQ_USER"),
    password: requiredEnv("HIVEMQ_PASS"),
    clientId: "rjl-fn-" + crypto.randomUUID().slice(0, 8),
    clean: true,
    connectTimeout: 6000,
    protocolVersion: 4,
  });

  await new Promise<void>((resolve, reject) => {
    const to = setTimeout(() => {
      try {
        client.end(true);
      } catch {
        // ignore
      }
      reject(new Error("mqtt timeout"));
    }, 9000);

    client.on("connect", () => {
      client.publish(topic, payload, { qos: 1, retain }, (err) => {
        clearTimeout(to);
        client.end(true, {}, () => (err ? reject(err) : resolve()));
      });
    });

    client.on("error", (e) => {
      clearTimeout(to);
      try {
        client.end(true);
      } catch {
        // ignore
      }
      reject(e);
    });
  });
}

// Look up a gate's signing secret (service-role only table).
export async function getGateSecret(db: ReturnType<typeof admin>, gateId: string): Promise<string | null> {
  const { data } = await db.from("gate_secrets").select("hmac_secret").eq("gate_id", gateId).maybeSingle();
  return data?.hmac_secret ?? null;
}

export async function updateGateServiceStatus(
  db: ReturnType<typeof admin>,
  gateId: string,
  serviceStatus: "active" | "suspended",
) {
  const { error } = await db.from("gates").update({ service_status: serviceStatus }).eq("id", gateId);
  if (error) throw error;
}

export async function publishOpen(gateId: string, secret: string) {
  const ts = Date.now();
  const sig = await hmacHex(secret, `open|${gateId}|${ts}`);
  await mqttPublish(
    `rjl/gate/${gateId}/cmd`,
    JSON.stringify({ cmd: "open", ts, sig }),
    false,
  );
}

export async function publishHold(gateId: string, secret: string, hold: "on" | "off") {
  const ts = Date.now();
  const sig = await hmacHex(secret, `hold|${gateId}|${hold}|${ts}`);
  await mqttPublish(
    `rjl/gate/${gateId}/control`,
    JSON.stringify({ hold, ts, sig }),
    true,
  );
}

export async function logGateAction(
  db: ReturnType<typeof admin>,
  entry: {
    gateId?: string | null;
    actionType: string;
    actionStatus: "accepted" | "rejected" | "success" | "ignored" | "error";
    actionSource: string;
    actorUserId?: string | null;
    stripeEventId?: string | null;
    detail?: Record<string, unknown>;
  },
) {
  const { error } = await db.from("gate_action_audit").insert({
    gate_id: entry.gateId ?? null,
    action_type: entry.actionType,
    action_status: entry.actionStatus,
    action_source: entry.actionSource,
    actor_user_id: entry.actorUserId ?? null,
    stripe_event_id: entry.stripeEventId ?? null,
    detail: entry.detail ?? {},
  });
  if (error) throw error;
}

export async function claimStripeWebhookEvent(
  db: ReturnType<typeof admin>,
  event: {
    eventId: string;
    eventType: string;
    subscriptionId?: string | null;
    payload: Record<string, unknown>;
  },
): Promise<boolean> {
  const { error } = await db.from("stripe_webhook_events").insert({
    event_id: event.eventId,
    event_type: event.eventType,
    subscription_id: event.subscriptionId ?? null,
    payload: event.payload,
  });
  if (!error) return true;
  if (error.code === "23505") {
    // A row already exists for this event_id (a Stripe retry). Only treat it as a
    // duplicate to skip when the first delivery was already handled successfully.
    // Rows still in 'received' or 'error' mean processing never completed, so we
    // allow reprocessing (Stripe retries non-2xx responses).
    const { data: existing, error: selectError } = await db
      .from("stripe_webhook_events")
      .select("processing_status")
      .eq("event_id", event.eventId)
      .maybeSingle();
    if (selectError) throw selectError;
    const status = existing?.processing_status;
    if (status === "processed" || status === "ignored") return false;
    return true;
  }
  throw error;
}

export async function completeStripeWebhookEvent(
  db: ReturnType<typeof admin>,
  eventId: string,
  update: {
    processingStatus: "processed" | "ignored" | "error";
    gateId?: string | null;
    result?: Record<string, unknown>;
  },
) {
  const { error } = await db.from("stripe_webhook_events").update({
    gate_id: update.gateId ?? null,
    processing_status: update.processingStatus,
    processed_at: new Date().toISOString(),
    result: update.result ?? {},
  }).eq("event_id", eventId);
  if (error) throw error;
}

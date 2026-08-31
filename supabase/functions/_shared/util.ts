// Shared helpers for RJL gate Edge Functions.
import { createClient } from "npm:@supabase/supabase-js@2";

export const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, stripe-signature",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

export function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "content-type": "application/json" },
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
  let diff = 0;
  const max = Math.max(a.length, b.length);
  diff |= a.length !== b.length ? 1 : 0;
  for (let i = 0; i < max; i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
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
    connectTimeout: 8000,
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

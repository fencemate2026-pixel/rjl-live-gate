// Shared helpers for RJL gate Edge Functions.
import { createClient } from "npm:@supabase/supabase-js@2";

// CORS for browser-called functions
export const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

export function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "content-type": "application/json" },
  });
}

// Service-role client — bypasses RLS, used to read the per-gate secret.
export const admin = () =>
  createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    { auth: { persistSession: false } },
  );

// HMAC-SHA256 -> lowercase hex (same scheme the firmware verifies).
export async function hmacHex(secret: string, msg: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Connect to HiveMQ over WSS, publish once, disconnect.
export async function mqttPublish(topic: string, payload: string, retain = false): Promise<void> {
  const mqtt = (await import("npm:mqtt@5")).default;
  const url = `wss://${Deno.env.get("HIVEMQ_HOST")}:8884/mqtt`;
  const client = mqtt.connect(url, {
    username: Deno.env.get("HIVEMQ_USER"),
    password: Deno.env.get("HIVEMQ_PASS"),
    clientId: "rjl-fn-" + crypto.randomUUID().slice(0, 8),
    clean: true,
    connectTimeout: 8000,
    protocolVersion: 4,
  });
  await new Promise<void>((resolve, reject) => {
    const to = setTimeout(() => { try { client.end(true); } catch (_) {} reject(new Error("mqtt timeout")); }, 9000);
    client.on("connect", () => {
      client.publish(topic, payload, { qos: 1, retain }, (err) => {
        clearTimeout(to);
        client.end(true, {}, () => (err ? reject(err) : resolve()));
      });
    });
    client.on("error", (e) => { clearTimeout(to); try { client.end(true); } catch (_) {} reject(e); });
  });
}

// Look up a gate's signing secret (service-role only table).
export async function getGateSecret(db: ReturnType<typeof admin>, gateId: string): Promise<string | null> {
  const { data } = await db.from("gate_secrets").select("hmac_secret").eq("gate_id", gateId).maybeSingle();
  return data?.hmac_secret ?? null;
}

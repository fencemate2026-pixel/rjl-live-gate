// RJL — Stripe webhook -> suspend / resume a gate.
//   payment good  -> publish signed {hold:"off"} (gate runs normally)
//   payment lapsed -> publish signed {hold:"on"}  (gate held open, access control suspended)
// The hold message is RETAINED, so a unit that's offline applies it on next connect.
//
// Deploy:  supabase functions deploy stripe-webhook --no-verify-jwt
//   (Stripe doesn't send a Supabase JWT; we authenticate via the Stripe signature instead.)

import Stripe from "npm:stripe@17";
import { admin, getGateSecret, hmacHex, mqttPublish } from "../_shared/util.ts";

const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!);
const cryptoProvider = Stripe.createSubtleCryptoProvider();
const WH_SECRET = Deno.env.get("STRIPE_WEBHOOK_SECRET")!;

async function suspend(gateId: string, hold: "on" | "off") {
  const db = admin();
  const secret = await getGateSecret(db, gateId);
  if (!secret) { console.log("no secret for gate", gateId); return; }
  const ts = Date.now();
  const sig = await hmacHex(secret, `hold|${gateId}|${hold}|${ts}`);
  await mqttPublish(`rjl/gate/${gateId}/control`, JSON.stringify({ hold, ts, sig }), true); // retained
  await db.from("gates").update({ service_status: hold === "on" ? "suspended" : "active" })
    .eq("id", gateId);
  console.log(`gate ${gateId} -> hold:${hold}`);
}

async function gateForSub(subId: string): Promise<string | null> {
  const { data } = await admin().from("gates").select("id").eq("stripe_subscription_id", subId).maybeSingle();
  return data?.id ?? null;
}

Deno.serve(async (req) => {
  const sig = req.headers.get("stripe-signature");
  if (!sig) return new Response("missing signature", { status: 400 });
  const body = await req.text();

  let event: Stripe.Event;
  try {
    event = await stripe.webhooks.constructEventAsync(body, sig, WH_SECRET, undefined, cryptoProvider);
  } catch (e) {
    return new Response(`bad signature: ${(e as Error).message}`, { status: 400 });
  }

  try {
    switch (event.type) {
      case "invoice.paid":
      case "invoice.payment_succeeded": {
        const sub = (event.data.object as any).subscription as string | null;
        if (sub) { const g = await gateForSub(sub); if (g) await suspend(g, "off"); }
        break;
      }
      case "customer.subscription.updated": {
        const s = event.data.object as Stripe.Subscription;
        const g = await gateForSub(s.id);
        if (g) {
          // 'unpaid' = Stripe has exhausted the dunning/grace window -> suspend.
          // 'active' = back in good standing -> resume. 'past_due' = still in grace, do nothing.
          if (s.status === "unpaid" || s.status === "canceled") await suspend(g, "on");
          else if (s.status === "active") await suspend(g, "off");
        }
        break;
      }
      case "customer.subscription.deleted": {
        const g = await gateForSub((event.data.object as Stripe.Subscription).id);
        if (g) await suspend(g, "on");
        break;
      }
      default:
        return new Response("ignored", { status: 200 });
    }
  } catch (e) {
    console.error("handler error", e);
    return new Response("handler error", { status: 500 }); // Stripe will retry
  }
  return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
});

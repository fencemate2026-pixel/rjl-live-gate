# RJL Gate — backend (Supabase Edge Functions + Stripe)

Two functions, one signing helper. This is what gets the HMAC secret **off the
client** and makes non-payment suspension automatic.

```
supabase/functions/
  _shared/util.ts           sign + MQTT publish + service-role helpers
  gate-open/index.ts        authenticated open (signs + publishes server-side)
  stripe-webhook/index.ts   Stripe events -> suspend / resume the gate
setup.sql                   schema: plan/status/stripe cols + locked secret table
```

## What it does
- **gate-open** — a logged-in user taps OPEN → browser calls this function with
  their JWT → function checks they're allowed on the gate, checks the gate isn't
  suspended, then signs `open|<id>|<ts>` and publishes it. The browser never sees
  the secret or the broker password.
- **stripe-webhook** — payment clears → signed `hold:off` (normal). Payment lapses
  past the grace window → signed `hold:on` (gate held open, retained). The firmware
  already enforces both.

## One-time deploy
1. Install CLI + link:
   ```
   npm i -g supabase
   supabase login
   supabase link --project-ref nwyrnezyzelsfvxascgf
   ```
2. Run **setup.sql** in the Supabase SQL Editor.
3. Set secrets (SUPABASE_URL / keys are injected automatically — don't set those):
   ```
   supabase secrets set \
     ALLOWED_ORIGINS=https://your-gate-app.example.com,https://your-preview-app.example.com \
     HIVEMQ_HOST=your-cluster.hivemq.cloud \
     HIVEMQ_USER=your-username \
     HIVEMQ_PASS='your-password' \
     STRIPE_SECRET_KEY=sk_live_xxx \
     STRIPE_WEBHOOK_SECRET=whsec_xxx
   ```
   `ALLOWED_ORIGINS` should list the exact front-end origins allowed to call `gate-open`.
4. Deploy:
   ```
   supabase functions deploy stripe-webhook --no-verify-jwt
   supabase functions deploy gate-open
   ```
   (`--no-verify-jwt` on the webhook because Stripe sends a Stripe signature, not a
   Supabase JWT — we verify that signature inside the function.)

## Stripe wiring
1. Product/Price: **Maintenance $59/month** recurring. Standard $710 is a separate
   one-off price / payment link.
2. When you start a client's subscription, write its id to that gate:
   `update gates set plan='maintenance', stripe_subscription_id='sub_xxx' where gate_id='...';`
3. Webhook endpoint → `https://nwyrnezyzelsfvxascgf.supabase.co/functions/v1/stripe-webhook`
   Events: `invoice.paid`, `invoice.payment_succeeded`, `customer.subscription.updated`,
   `customer.subscription.deleted`. Copy its signing secret into STRIPE_WEBHOOK_SECRET.
4. **Grace period = Stripe's job.** Settings → Billing → *Manage failed payments*:
   set "after retries, mark subscription **unpaid**" to ~14 days. The function only
   suspends when Stripe flips the sub to `unpaid`/`canceled`, so your contractual
   grace window and the tech stay in sync automatically.

## Front-end
Use the new `gate.html` (one folder up). Fill in `SUPABASE_ANON` (public anon key)
and create the client's user in Supabase Auth + a row in `gate_users` linking that
user to the gate. The page holds no secret and no broker password.

## Test
```
stripe listen --forward-to https://nwyrnezyzelsfvxascgf.supabase.co/functions/v1/stripe-webhook
stripe trigger invoice.payment_failed     # then watch:
supabase functions logs stripe-webhook
```
Suspend should publish a retained `hold:on`; the unit's serial prints
`[hold] SUSPENDED — gate held open`. Resume with `stripe trigger invoice.paid`.

## Local validation
```
deno check supabase/functions/gate-open/index.ts
deno check supabase/functions/stripe-webhook/index.ts
```

## Known test points (I can't verify these from here)
- **MQTT-from-Deno**: `npm:mqtt` over WSS should work in the edge runtime; if a
  publish ever times out in the logs, that's the first place to look.
- **Stripe `invoice.subscription`** field can be null on some invoice types — the
  code guards for it, but confirm your subscription invoices carry it.

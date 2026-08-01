-- RJL gate backend — schema additions.
-- Run in the Supabase SQL Editor of project nwyrnezyzelsfvxascgf.
-- NOTE: the gates table's primary key is `id` (text), e.g. 'demo-0001'.
--       gate_users.gate_id and gate_secrets.gate_id both reference gates.id.

-- 1. Plan + service status + Stripe link on each gate
alter table public.gates add column if not exists plan text
  check (plan in ('standard','maintenance')) default 'standard';
alter table public.gates add column if not exists service_status text
  check (service_status in ('active','suspended')) default 'active';
alter table public.gates add column if not exists stripe_customer_id text;
alter table public.gates add column if not exists stripe_subscription_id text;
create index if not exists gates_stripe_sub_idx on public.gates(stripe_subscription_id);

-- 2. Per-gate signing secret, readable ONLY by the service role (RLS on, no policies).
--    The Edge Functions use the service-role key, which bypasses RLS.
create table if not exists public.gate_secrets (
  gate_id      text primary key references public.gates(id) on delete cascade,
  hmac_secret  text not null,
  created_at   timestamptz default now()
);
alter table public.gate_secrets enable row level security;
-- (intentionally no policies)

-- 3. Seed each unit's secret at flash time. Do NOT commit real HMAC values.
-- insert into public.gate_secrets (gate_id, hmac_secret)
-- values ('your-gate-id', 'your_unique_hmac_secret')
-- on conflict (gate_id) do update set hmac_secret = excluded.hmac_secret;

-- 4. Let the browser READ its gates' status (never the secret).
alter table public.gates enable row level security;
drop policy if exists "users read their gates" on public.gates;
create policy "users read their gates" on public.gates
  for select using (
    exists (select 1 from public.gate_users gu
            where gu.gate_id = gates.id and gu.user_id = auth.uid())
  );

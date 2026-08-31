-- RJL Live Gate — bootstrap for project aevsfrxqyvtuycufffxk
-- Run in Supabase → SQL Editor → New query → Run.

create table if not exists public.gates (
  id text primary key,
  name text,
  plan text check (plan in ('standard','maintenance')) default 'standard',
  service_status text check (service_status in ('active','suspended')) default 'active',
  stripe_customer_id text,
  stripe_subscription_id text,
  created_at timestamptz default now()
);

create table if not exists public.gate_users (
  id bigserial primary key,
  gate_id text not null references public.gates(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  unique (gate_id, user_id)
);

create table if not exists public.gate_secrets (
  gate_id     text primary key references public.gates(id) on delete cascade,
  hmac_secret text not null,
  created_at  timestamptz default now()
);

alter table public.gates add column if not exists plan text;
alter table public.gates add column if not exists service_status text;
alter table public.gates add column if not exists stripe_customer_id text;
alter table public.gates add column if not exists stripe_subscription_id text;

create index if not exists gates_stripe_sub_idx on public.gates(stripe_subscription_id);

alter table public.gates enable row level security;
alter table public.gate_users enable row level security;
alter table public.gate_secrets enable row level security;

drop policy if exists "users read their gates" on public.gates;
create policy "users read their gates" on public.gates
  for select using (
    exists (
      select 1 from public.gate_users gu
      where gu.gate_id = gates.id and gu.user_id = auth.uid()
    )
  );

drop policy if exists "users read own gate links" on public.gate_users;
create policy "users read own gate links" on public.gate_users
  for select using (user_id = auth.uid());

-- No policies on gate_secrets: service role only.

insert into public.gates (id, name, plan, service_status)
values ('demo-0001', 'Demo gate', 'maintenance', 'active')
on conflict (id) do update set service_status = excluded.service_status;

insert into public.gate_secrets (gate_id, hmac_secret)
values ('demo-0001', '952637466aae5d1e751098b9a9c57b80')
on conflict (gate_id) do update set hmac_secret = excluded.hmac_secret;

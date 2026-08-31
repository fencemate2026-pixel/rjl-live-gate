-- RJL gate backend — blank-project bootstrap for Supabase project aevsfrxqyvtuycufffxk.
-- Run in the Supabase SQL Editor before deploying the Edge Functions.

-- 1. Core gate records used by the front-end and Edge Functions.
create table if not exists public.gates (
  id                     text primary key,
  name                   text,
  plan                   text not null default 'standard'
    check (plan in ('standard', 'maintenance')),
  service_status         text not null default 'active'
    check (service_status in ('active', 'suspended')),
  stripe_customer_id     text,
  stripe_subscription_id text,
  created_at             timestamptz not null default now()
);

alter table public.gates
  add column if not exists name text,
  add column if not exists plan text,
  add column if not exists service_status text,
  add column if not exists stripe_customer_id text,
  add column if not exists stripe_subscription_id text,
  add column if not exists created_at timestamptz not null default now();

alter table public.gates
  alter column plan set default 'standard',
  alter column service_status set default 'active';

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'gates_plan_check'
      and conrelid = 'public.gates'::regclass
  ) then
    alter table public.gates
      add constraint gates_plan_check
      check (plan in ('standard', 'maintenance'));
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'gates_service_status_check'
      and conrelid = 'public.gates'::regclass
  ) then
    alter table public.gates
      add constraint gates_service_status_check
      check (service_status in ('active', 'suspended'));
  end if;
end $$;

create index if not exists gates_stripe_sub_idx on public.gates(stripe_subscription_id);

-- 2. Gate-to-user links. Add a row here after creating a Supabase Auth user.
create table if not exists public.gate_users (
  gate_id    text not null references public.gates(id) on delete cascade,
  user_id    uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (gate_id, user_id)
);

alter table public.gate_users enable row level security;
-- No direct browser policies required; the service role handles authorization checks.

-- 3. Per-gate signing secret, readable only by the service role.
create table if not exists public.gate_secrets (
  gate_id      text primary key references public.gates(id) on delete cascade,
  hmac_secret  text not null,
  created_at   timestamptz not null default now()
);

alter table public.gate_secrets enable row level security;
-- Intentionally no policies.

-- 4. Seed the demo gate used by gate.html / index.html.
insert into public.gates (id, name, plan, service_status)
values ('demo-0001', 'Demo Gate', 'standard', 'active')
on conflict (id) do nothing;

insert into public.gate_secrets (gate_id, hmac_secret)
values ('demo-0001', '952637466aae5d1e751098b9a9c57b80')
on conflict (gate_id) do nothing;

-- 5. Let signed-in linked users read only their own gate state from the browser.
alter table public.gates enable row level security;

drop policy if exists "users read their gates" on public.gates;
create policy "users read their gates" on public.gates
  for select using (
    exists (
      select 1
      from public.gate_users gu
      where gu.gate_id = gates.id
        and gu.user_id = auth.uid()
    )
  );

-- Gate action audit trail and Stripe webhook idempotency.
-- Apply with Supabase migrations or in the SQL editor after setup.sql.

create table if not exists public.gate_action_audit (
  id                bigint generated always as identity primary key,
  gate_id           text references public.gates(id) on delete cascade,
  action_type       text not null,
  action_status     text not null default 'accepted',
  action_source     text not null,
  actor_user_id     uuid,
  stripe_event_id   text,
  detail            jsonb not null default '{}'::jsonb,
  created_at        timestamptz not null default now(),
  constraint gate_action_audit_status_check
    check (action_status in ('accepted','rejected','success','ignored','error'))
);

create index if not exists gate_action_audit_gate_idx
  on public.gate_action_audit(gate_id, created_at desc);

create index if not exists gate_action_audit_event_idx
  on public.gate_action_audit(stripe_event_id)
  where stripe_event_id is not null;

alter table public.gate_action_audit enable row level security;

drop policy if exists "users read their gate action audit" on public.gate_action_audit;
create policy "users read their gate action audit" on public.gate_action_audit
  for select using (
    exists (
      select 1
      from public.gate_users gu
      where gu.gate_id = gate_action_audit.gate_id
        and gu.user_id = auth.uid()
    )
  );

create table if not exists public.stripe_webhook_events (
  event_id          text primary key,
  event_type        text not null,
  subscription_id   text,
  gate_id           text references public.gates(id) on delete set null,
  processing_status text not null default 'received',
  received_at       timestamptz not null default now(),
  processed_at      timestamptz,
  payload           jsonb not null,
  result            jsonb not null default '{}'::jsonb,
  constraint stripe_webhook_events_status_check
    check (processing_status in ('received','processed','ignored','error'))
);

create index if not exists stripe_webhook_events_subscription_idx
  on public.stripe_webhook_events(subscription_id);

alter table public.stripe_webhook_events enable row level security;
-- No policies: webhook event payloads stay service-role only.

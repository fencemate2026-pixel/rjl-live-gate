# Connected project: aevsfrxqyvtuycufffxk

Frontend now uses:
- URL: https://aevsfrxqyvtuycufffxk.supabase.co
- Publishable key: <YOUR_SUPABASE_PUBLISHABLE_KEY>

## You still must do this in the Supabase dashboard

1. SQL Editor \u2192 paste and run `setup.sql`
2. Authentication \u2192 Users \u2192 Add user (email + password)
3. SQL Editor, after the user exists:

```sql
insert into public.gate_users (gate_id, user_id)
select 'demo-0001', id from auth.users where email = 'YOUR_EMAIL_HERE'
on conflict do nothing;
```

4. Edge Functions (from a machine with Supabase CLI):

```bash
supabase link --project-ref aevsfrxqyvtuycufffxk
supabase secrets set HIVEMQ_HOST=YOUR_CLUSTER.s1.eu.hivemq.cloud HIVEMQ_USER=gate-app HIVEMQ_PASS='YOUR_BROKER_PASS'
supabase functions deploy gate-open
```

Do not put the service_role key or HiveMQ password in the frontend.
Copy the publishable key from the Supabase project dashboard when configuring the live frontend.

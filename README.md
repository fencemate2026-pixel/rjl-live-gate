# RJL Live Gate — full project

Root files:
- `rjl_gate_anywhere.ino` -> open in Arduino IDE for the firmware
- `plan-select.html`, `gate.html`, `index.html`, `rjl-logo-transparent.png` -> host on Vercel/Netlify
- `index.ts`, `util.ts`, `setup.sql`, `README-backend.md` -> backend/Supabase deployment assets
- `supabase/functions/` -> deployable Supabase Edge Functions for `gate-open` and `stripe-webhook`

Automation:
- GitHub Actions runs `.github/workflows/repo-automation-sync.yml` on pushes and pull requests to keep the core project files and hosted app configuration in sync.

Per-unit at the bench: set GATE_ID + HMAC_SECRET in the .ino, add the matching
row in gates + gate_secrets, generate that client's gate.html config, flash.

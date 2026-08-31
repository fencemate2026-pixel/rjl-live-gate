# RJL Live Gate — full project

firmware/rjl_gate_anywhere/   -> open rjl_gate_anywhere.ino in Arduino IDE
web/                          -> plan-select.html, gate.html, logo (host on Vercel/Netlify)
backend/                      -> run the Supabase CLI from HERE (see backend/README-backend.md)

Automation:
- GitHub Actions runs `.github/workflows/repo-automation-sync.yml` on pushes and pull requests to keep the core project files and hosted app configuration in sync.

Per-unit at the bench: set GATE_ID + HMAC_SECRET in the .ino, add the matching
row in gates + gate_secrets, generate that client's gate.html config, flash.

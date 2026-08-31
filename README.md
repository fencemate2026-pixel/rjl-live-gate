# RJL Live Gate — full project

firmware/rjl_gate_anywhere/   -> open rjl_gate_anywhere.ino in Arduino IDE
public/                       -> production Netlify site
plan-select.html, gate.html   -> legacy/reference web screens
backend/                      -> run the Supabase CLI from HERE (see backend/README-backend.md)

Per-unit at the bench: set GATE_ID + HMAC_SECRET in the .ino, add the matching
row in gates + gate_secrets, generate that client's gate.html config, flash.

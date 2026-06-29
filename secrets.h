#pragma once
// =============================================================
//  RJL Live Gate - per-unit secrets.  DO NOT COMMIT THIS FILE.
//  Gitignored via **/secrets.h. One copy sits next to the .ino.
//
//  PER GATE YOU BUILD: change GATE_ID + HMAC_SECRET below (and
//  add the matching row in the Supabase gate_secrets table so
//  the two halves agree), then flash. Nothing else changes.
// =============================================================

// ---- Per-UNIT identity (unique to every gate) ----
#define SECRET_GATE_ID      "demo-0001"
#define SECRET_HMAC_SECRET  "952637466aae5d1e751098b9a9c57b80"

// ---- On-site tap-page PIN ----
#define SECRET_LOCAL_PIN    "1234"

// ---- HiveMQ broker login (shared across fleet for now) ----
#define SECRET_MQTT_USER    "RJLCOMMERCIAL"
#define SECRET_MQTT_PASS    "Alebakis1!"

// ---- Site WiFi ----
//  Only needed if this build hardcodes WiFi. If you provision
//  over the RJL-Gate captive portal (WiFiManager), delete these
//  two lines and skip their .ino edits.
#define SECRET_WIFI_SSID    "Starlinkwifi"
#define SECRET_WIFI_PASS    "wa9acpnyjrbg"

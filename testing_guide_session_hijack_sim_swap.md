# Testing Guide: Session Hijacking & SIM Swap Detection Demo

This walks you through demonstrating your MFA Guard project live to your professors — covering login/MFA, session-hijacking detection, and SIM-swap detection, using the app's own built-in simulation tools plus a couple of manual tests that prove the logic (not just canned demo buttons).

---

## 0. Setup (before the demo)

1. From the project folder, install dependencies and run:
   ```
   pip install -r requirements.txt
   python app.py
   ```
2. Open `http://127.0.0.1:5000` in your browser.
3. Log in with a demo account from `passwords.txt` (e.g. `admin` / `admin123`).
4. Since `MFA_GUARD_DEV_LOG_OTP=true` is set in `.env`, the OTP code is printed in your terminal instead of being emailed/texted — watch the terminal for a line like:
   ```
   MFA Guard development OTP for login (admin): 439217
   ```
   Enter that code on the MFA verification screen.

**Tip for the demo:** keep the terminal visible on screen (or shared) so professors can see the OTP being generated and, later, the anomaly detection logs firing in real time — it makes the detection feel less like a black box.

---

## Part A — Session Hijacking Detection

### A1. Show a clean, low-risk session (baseline)
1. After logging in, go to the **Dashboard**.
2. Click **Sessions** in the nav to show your current session: consistent IP, device fingerprint, and location.
3. Explain: every session gets a `risk_score` computed from features like geo-velocity, device fingerprint match, user-agent match, time of day, and VPN/Tor/datacenter detection (this is `detector.py`, `RulesEngine`).

### A2. Trigger a realistic hijack scenario — "impossible travel"
This is the most convincing test because it's driven by your actual detection math, not a hardcoded demo value.

1. On the **Dashboard**, click **Simulate Attack**. This randomly fires one of four scenarios your app defines: `session_hijacking`, `impossible_travel`, `device_mismatch`, `vpn_tor_datacenter` (see `simulateAttack()` in `dashboard.js`).
2. Click it a few times until you land on **impossible_travel** or **session_hijacking** — you'll see a toast message and the risk score update.
3. Go to **Anomalies** — the event now appears with its risk score and the rule(s) that fired.
4. Go to **Sessions** — the flagged session shows `step_up_auth` or `block_session` as the recommendation, depending on score.
5. **Explain to professors:** the scoring is rule-based and additive (`RulesEngine` in `detector.py`) — e.g. impossible travel = +40, device mismatch = +25, VPN/Tor/datacenter = +25, unusual time = +10 — capped at 100, then mapped to `allow / monitor / step_up_auth / block_session` via configurable thresholds.

### A3. Prove it's not hardcoded — trigger detection manually via the API
This is the strongest evidence for a professor that the detection logic actually evaluates request data, not just a demo button.

1. Open browser DevTools → Console (while logged in).
2. Run:
   ```javascript
   fetch('/api/evaluate-session', {
     method: 'POST',
     headers: {
       'Content-Type': 'application/json',
       'X-CSRFToken': document.querySelector('meta[name=csrf-token]').content
     },
     body: JSON.stringify({ ip_address: "185.220.101.1" }) // known Tor/anonymized exit range
   }).then(r => r.json()).then(console.log)
   ```
3. Show the returned JSON: `geo_velocity` will be huge (impossible speed from your real location to that IP's location within seconds), `risk_score` climbs, `triggered_rules` lists `impossible_travel`, and `recommendation` moves to `monitor`/`step_up_auth`.
4. Change just the IP to your own local one again and re-run — show the score drops back to 0. This proves the score responds to the actual computed distance/time, not a fixed value.

### A4. Show the reauthentication enforcement
1. After a session is flagged `step_up_auth` or `block_session` (from A2), try navigating to any page (e.g. Dashboard).
2. You'll be redirected to `/reauth` — the app is actively enforcing the policy, not just logging it. Enter your password to prove identity and resume.
3. This demonstrates the `enforce_reauthentication` before-request hook in `app.py`.

---

## Part B — SIM Swap Detection

### B1. Explain the concept first (30 seconds)
SIM swap attacks let an attacker receive a victim's SMS/calls (including SMS-based MFA codes) by porting their number to a new SIM. Your detector correlates carrier/IMSI changes with other risk signals (recent password reset, new device, impossible travel) rather than trusting carrier change alone.

### B2. Run the built-in simulation
1. Go to **SIM Swap** page in the nav.
2. Click **Simulate SIM Swap**. This sends a realistic payload (see `simulateSIMSwap()` in `dashboard.js`):
   - carrier changed (Verizon → Unknown MVNO)
   - IMSI changed
   - recent password reset = true
   - new device detected = true
   - geo-velocity = 900 (impossible travel)
3. The event appears in the **SIM Swap Events** table with a risk score and the list of signals that fired.
4. **Explain the math:** in `check_sim_swap_indicators()` — carrier change +25, IMSI change +35, recent password reset +20, new device +20, geo-velocity > 500 → impossible travel +30, capped at 100. A score ≥ 60 flags the account `is_compromised`, which forces re-authentication on that user (`db.force_reauth`).

### B3. Show partial-signal cases (to prove it's not all-or-nothing)
This is a good question professors often ask: "what if only one signal fires?" You can demonstrate this via DevTools console while on the SIM Swap page (admin session required):
```javascript
fetch('/api/check-sim-swap', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRFToken': document.querySelector('meta[name=csrf-token]').content
  },
  body: JSON.stringify({ user_id: 3, old_carrier: "Verizon", new_carrier: "Verizon" }) // no actual change
}).then(r => r.json()).then(console.log)
```
- No signals changed → `risk_score: 0`, `is_compromised: false`.
- Now change only `new_carrier` to something different and re-run → only `carrier_changed` fires, score 25, still below the 60 compromise threshold → `is_compromised: false`, showing the system requires corroborating evidence, not a single weak signal, before forcing re-auth.

### B4. Show enforcement
After B2 (full scenario, is_compromised = true), check the **Sessions** page for that user (id 3) — it should now show `requires_reauth`. Log in as that demo user (if you have credentials) to show they get redirected to `/reauth` on their next request.

---

## Part C — Talking points if professors ask "how would this hold up in production?"

Be upfront about these — it shows maturity, not weakness:

- **GeoIP/VPN/Tor/carrier data is currently simulated** (`utils/geo_ip.py`) for local demo purposes rather than pulled from a live threat-intel or telecom API — in production you'd integrate a real GeoIP provider and carrier-lookup API.
- **The `X-Demo-IP` header and API `override` fields** (in `detector.extract_features`) exist specifically so you can simulate different IPs/devices without needing to physically be elsewhere — flag that these would be removed/disabled in production since they let a client claim any IP.
- **Password hashing** already uses `werkzeug.security` (PBKDF2/scrypt), with a legacy-plaintext-hash fallback path in `database.py` for migration purposes — worth mentioning you're aware of it.
- **Rate limiting is in-memory** (`rate_limits = {}` in `app.py`) — fine for a single-process demo, but you'd move to Redis or similar for multi-instance production deployments.

---

## Quick demo script (5 minutes, if time is short)

1. Log in → show MFA step (30s)
2. Dashboard → click **Simulate Attack** twice until impossible_travel fires → show Anomalies page (1 min)
3. DevTools console → run the manual `evaluate-session` call with a foreign IP → show live risk score change (1.5 min)
4. SIM Swap page → click **Simulate SIM Swap** → show risk score + signals table (1 min)
5. Try navigating a page on the flagged session → show forced `/reauth` redirect (1 min)

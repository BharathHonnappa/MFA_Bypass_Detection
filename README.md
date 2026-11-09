# MFA Guard - MFA Bypass Detection MVP

MFA Guard is a Flask mini project for detecting **MFA bypass after login**. The main idea is that attackers may pass or bypass MFA once, then abuse the session through session hijacking, stolen cookies, device changes, impossible travel, VPN/Tor infrastructure, or SIM swap attacks. This app demonstrates how an enterprise security team can monitor those post-authentication anomalies and force re-authentication.

## Project Goal

Build an enterprise-style system where:

- Employees log in with password + OTP MFA.
- Employee sessions are monitored after MFA succeeds.
- Suspicious post-authentication behavior creates anomalies.
- High-risk sessions require step-up re-authentication.
- Admin/security users can monitor all employees and respond to threats.

This project is now structured as an MVP-style Flask application. It still uses SQLite by default, but includes product hardening hooks for CSRF, rate limiting, environment configuration, SMTP-backed MFA code delivery, soft user deactivation, account operations, polished errors, and Gunicorn deployment.

## User Roles

### Admin

Admins represent the security team. They can access:

- Dashboard
- Sessions
- Anomalies
- SIM Swap
- Settings
- Admin

Admins can:

- View company-wide active sessions.
- View employee risk scores.
- Review anomaly alerts.
- Simulate attacks for demo/testing.
- Force re-authentication for one employee or all high-risk employees.
- Terminate suspicious sessions.
- Resolve anomalies or mark them false positive.
- View security event logs.

### Employee

Employees represent normal company users. They should **not** see company-wide monitoring pages.

Employees can access:

- Login
- MFA verification
- My Security dashboard
- Re-authentication page
- Logout

Employees can:

- View only their own account security status.
- View their own active sessions.
- View recent security activity for their own account.
- Complete step-up re-authentication when suspicious activity is detected.
- Terminate their own sessions.

## Real-Life Example

Alice is an employee. She logs in from her company laptop in New York and completes MFA. Her session is normal.

Later, the same session appears from a different country with a different browser fingerprint. This suggests the attacker may have stolen Alice's session cookie after MFA.

The system detects:

- Different IP/location
- Device fingerprint mismatch
- User-agent change
- Impossible travel
- High risk score

The app then:

- Logs an anomaly.
- Updates Alice's session risk score.
- Requires Alice to complete step-up re-authentication.
- Shows the incident to the admin in Dashboard, Sessions, and Anomalies.

For SIM swap, Bob may have SMS MFA enabled. If his carrier and IMSI change, followed by a password reset or new-device login, the system records a SIM swap event and can force Bob to re-authenticate.

## Current Demo Accounts

| Role | Username | Password |
| --- | --- | --- |
| Admin | `admin` | `admin123` |
| Employee | `alice` | `pass123` |
| Employee | `bob` | `pass123` |
| Employee | `charlie` | `pass123` |

OTP codes are delivered through the configured MFA provider. Set SMTP variables in `.env` for email delivery. Development terminal logging is available only when `MFA_GUARD_DEV_LOG_OTP=true`.

## Main Files

| File | Purpose |
| --- | --- |
| `app.py` | Flask routes, auth flow, role enforcement, re-auth enforcement, APIs |
| `database.py` | SQLite schema, migrations, seed users, session/anomaly/event helpers |
| `detector.py` | Deterministic rules engine for session anomaly and SIM swap risk scoring |
| `mfa_provider.py` | MFA code delivery abstraction with SMTP and explicit development logging |
| `wsgi.py` | Gunicorn/uWSGI import target |
| `gunicorn.conf.py` | Production Gunicorn defaults driven by environment variables |
| `.env.example` | Required production configuration template |
| `demo_data.py` | Loads sample users, sessions, anomalies, and SIM swap events |
| `utils/geo_ip.py` | Simulated GeoIP lookup, distance, velocity, VPN/Tor/datacenter checks |
| `utils/device_fingerprint.py` | Older standalone fingerprint helper, currently not central to the new flow |
| `templates/base.html` | Shared layout and role-aware navigation |
| `templates/login.html` | Password login page with browser fingerprint collection |
| `templates/mfa_verify.html` | OTP verification page |
| `templates/employee_dashboard.html` | Employee-only My Security dashboard |
| `templates/dashboard.html` | Admin security overview |
| `templates/sessions.html` | Admin active session monitoring |
| `templates/anomalies.html` | Admin anomaly queue |
| `templates/sim_swap.html` | Admin SIM swap monitoring |
| `templates/settings.html` | Admin detection policy view |
| `templates/admin_dashboard.html` | Admin employee risk overview |
| `templates/reauth.html` | Step-up re-authentication page |
| `static/js/dashboard.js` | Shared UI actions, charts, simulations, resolve/terminate APIs |
| `static/css/dashboard.css` | Enterprise-style dashboard/auth styling |

## Route Model

### Public/Auth

- `GET /` redirects based on auth state and role.
- `GET/POST /login` starts password login.
- `GET/POST /mfa-verify` verifies OTP and creates a monitored session.
- `GET /logout` ends the current session.

### Employee

- `GET /employee` shows the employee's personal security dashboard.
- `GET /reauth` shows step-up verification when a session is risky.
- `POST /reauth-verify` verifies password + OTP and clears the risky session state.
- `GET /api/my/security-events` returns only the logged-in user's events.

### Admin

- `GET /dashboard`
- `GET /sessions`
- `GET /anomalies`
- `GET /sim-swap`
- `GET /settings`
- `GET /admin`
- `GET /api/stats/realtime`
- `GET /api/anomalies/recent`
- `GET /api/security-events`
- `POST /api/check-sim-swap`
- `POST /api/simulate-attack`
- `POST /api/force-reauth`
- `POST /api/users/<id>/edit`
- `POST /api/users/<id>/reset-password`
- `POST /api/users/<id>/delete` deactivates the user and preserves audit records.
- `POST /api/users/<id>/reactivate`
- `POST /api/anomalies/<id>/resolve`
- `POST /api/anomalies/<id>/false-positive`

### Shared Authenticated API

- `POST /api/evaluate-session` evaluates the current user's active session.
- `POST /api/sessions/<id>/terminate` lets admins terminate any session and employees terminate only their own sessions.

## Detection Rules

Session anomaly detection currently uses deterministic rules:

| Rule | Meaning |
| --- | --- |
| `impossible_travel` | Session appears from a distant location faster than possible travel |
| `device_mismatch` | Device/browser fingerprint changed after MFA |
| `user_agent_changed` | Browser user-agent changed after MFA |
| `unusual_time` | Access outside normal hours |
| `vpn_tor_datacenter` | Access from VPN, Tor, or datacenter infrastructure |
| `rapid_requests` | Request rate is too high for a normal employee session |

SIM swap detection uses:

- Carrier change
- IMSI change
- Recent password reset
- New device detection
- Impossible travel around the phone change

## Risk Response Policy

| Risk Score | Response |
| --- | --- |
| `0-29` | Allow |
| `30-59` | Monitor and log |
| `60-79` | Require step-up re-authentication |
| `80-100` | Block until identity is verified |

The app stores this state on the active session:

- `risk_score`
- `requires_reauth`
- `blocked`
- `reauth_reason`

A Flask `before_request` hook redirects users with `requires_reauth = 1` to `/reauth` before they can continue using protected pages.

## Database Tables

- `users`
- `sessions`
- `request_logs`
- `anomalies`
- `sim_swap_events`
- `security_events`

The database layer includes lightweight migrations for new columns such as `role`, `department`, `mfa_method`, `requires_reauth`, `blocked`, `severity`, and SIM swap `status`.

Security event logs are append-only through the application. User deactivation no longer deletes sessions, anomalies, SIM swap events, or security events.

## Run Locally

Using the user's requested virtual environment:

```bash
source ~/impacket_venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# For local-only development without SMTP, set MFA_GUARD_ENV=development and MFA_GUARD_DEV_LOG_OTP=true in .env.
python demo_data.py
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

## Verification Commands

```bash
source ~/impacket_venv/bin/activate
python -m py_compile app.py database.py detector.py demo_data.py utils/device_fingerprint.py utils/geo_ip.py
python -c "import app; app.db.init_db(); print('app import and db init ok')"
```

## Production Run

Use a real secret key and SMTP provider in `.env`, keep `MFA_GUARD_DEV_LOG_OTP=false`, and run behind HTTPS:

```bash
source .venv/bin/activate
pip install -r requirements.txt
gunicorn -c gunicorn.conf.py wsgi:application
```

Place Nginx or another reverse proxy in front of Gunicorn, terminate TLS there, and set `MFA_GUARD_COOKIE_SECURE=true`. For multi-user production deployments, move from SQLite to PostgreSQL and replace the lightweight migration helpers with Alembic or Flask-Migrate.

## Current Implementation Status

Completed or in progress:

- Role-based admin vs employee access model.
- Admin-only monitoring pages.
- Employee-only My Security page.
- Password + OTP login flow for both admins and employees.
- Step-up re-authentication flow.
- Deterministic anomaly scoring instead of random risk.
- Persistent anomaly and SIM swap logging.
- Force re-authentication API.
- Resolve/false-positive anomaly APIs.
- Session termination authorization.
- Enterprise-style UI cleanup.

Still recommended before final submission:

- Add automated tests with Flask test client for login, admin actions, permissions, session termination, and settings saves.
- Add WebAuthn/TOTP enrollment if authenticator-app MFA should be self-service instead of email-delivered codes.
- Decide whether to keep or remove the checked-in `mfa_security.db` file.
- Clean up old generated files like `__pycache__/`.

## Production Caveats

For real enterprise use, this would need:

- Server-side session storage.
- Server-side sessions backed by Redis or a database.
- TOTP/WebAuthn/push MFA enrollment and recovery workflows.
- User-facing forgot-password/account recovery with abuse controls.
- Audit-log retention and tamper resistance.
- Real GeoIP, VPN/Tor, ASN, and carrier intelligence APIs.
- SIEM/SOAR integration.
- Stronger admin authorization and least-privilege role tiers.
- Privacy review for employee monitoring data.

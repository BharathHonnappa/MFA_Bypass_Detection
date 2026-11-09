import json
import os
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

if load_dotenv:
    load_dotenv()

from database import Database
from detector import AnomalyDetector
from mfa_provider import MFAProvider, MFAProviderError

app = Flask(__name__)
app.secret_key = os.environ.get("MFA_GUARD_SECRET_KEY", "dev-only-change-me")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=os.environ.get("MFA_GUARD_COOKIE_SAMESITE", "Lax"),
    SESSION_COOKIE_SECURE=os.environ.get("MFA_GUARD_COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=int(os.environ.get("MFA_GUARD_SESSION_MINUTES", "60"))),
    MAX_CONTENT_LENGTH=int(os.environ.get("MFA_GUARD_MAX_CONTENT_LENGTH", "1048576")),
)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

db = Database(os.environ.get("MFA_GUARD_DB", "mfa_security.db"))
detector = AnomalyDetector()
mfa_provider = MFAProvider()
rate_limits = {}

RATE_LIMITS = {
    "login": (8, 300),
    "mfa": (6, 300),
    "reauth": (6, 300),
    "api_post": (120, 60),
    "admin_action": (30, 300),
}

if os.environ.get("MFA_GUARD_ENV") == "production" and app.secret_key == "dev-only-change-me":
    raise RuntimeError("Set MFA_GUARD_SECRET_KEY before running outside debug mode.")


class User(UserMixin):
    def __init__(self, user_id, username, email, phone, role="employee", department="", mfa_method="Authenticator App"):
        self.id = user_id
        self.username = username
        self.email = email
        self.phone = phone
        self.role = role
        self.department = department
        self.mfa_method = mfa_method

    @property
    def is_admin(self):
        return self.role == "admin"


@login_manager.user_loader
def load_user(user_id):
    user_data = db.get_user(user_id)
    return User(*user_data) if user_data else None


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            flash("You do not have access to the security console.", "warning")
            return redirect(url_for("employee_dashboard"))
        return view(*args, **kwargs)
    return wrapped


def current_session_data():
    session_id = session.get("active_session_id")
    return db.get_session_data(current_user.id, session_id) if current_user.is_authenticated else None


def get_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf_token():
    token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
    return bool(token and secrets.compare_digest(token, session.get("_csrf_token", "")))


def csrf_failure():
    if request.path.startswith("/api/"):
        return jsonify({"error": "Invalid or missing CSRF token"}), 400
    flash("Your form expired. Please try again.", "warning")
    return redirect(request.referrer or url_for("login"))


def client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    return (forwarded.split(",")[0].strip() or request.remote_addr or "unknown")


def check_rate_limit(scope, identifier):
    max_attempts, window_seconds = RATE_LIMITS[scope]
    now = time.time()
    key = f"{scope}:{identifier or 'unknown'}"
    attempts = [ts for ts in rate_limits.get(key, []) if now - ts < window_seconds]
    if len(attempts) >= max_attempts:
        rate_limits[key] = attempts
        retry_after = int(window_seconds - (now - attempts[0]))
        return False, max(retry_after, 1)
    attempts.append(now)
    rate_limits[key] = attempts
    return True, 0


def clear_rate_limit(scope, identifier):
    rate_limits.pop(f"{scope}:{identifier or 'unknown'}", None)


def rate_limited_response(scope, identifier, message):
    allowed, retry_after = check_rate_limit(scope, identifier)
    if allowed:
        return None
    full_message = f"{message} Try again in {retry_after} seconds."
    if request.path.startswith("/api/"):
        return jsonify({"error": full_message}), 429
    return full_message


def password_policy_error(password):
    if len(password) < 12:
        return "Password must be at least 12 characters."
    checks = [
        any(ch.islower() for ch in password),
        any(ch.isupper() for ch in password),
        any(ch.isdigit() for ch in password),
        any(not ch.isalnum() for ch in password),
    ]
    if sum(checks) < 3:
        return "Password must include at least three of: uppercase, lowercase, number, symbol."
    return None


def normalize_role(role):
    return role if role in ("employee", "admin") else "employee"


def verify_otp(context, code):
    expires_at = session.get("otp_expires_at")
    if session.get("otp_context") != context or not code or code != session.get("otp_code"):
        return False
    if not expires_at:
        return False
    try:
        return datetime.now() <= datetime.fromisoformat(expires_at)
    except ValueError:
        return False


@app.before_request
def protect_post_requests():
    if request.method != "POST":
        return None
    if not validate_csrf_token():
        return csrf_failure()
    if request.path.startswith("/api/"):
        limited = rate_limited_response("api_post", f"{client_ip()}:{current_user.get_id() if current_user.is_authenticated else 'anon'}", "Too many API actions.")
        if limited:
            return limited
        if current_user.is_authenticated and current_user.is_admin:
            admin_limited = rate_limited_response("admin_action", f"{client_ip()}:{current_user.id}", "Too many admin actions.")
            if admin_limited:
                return admin_limited
    return None


@app.before_request
def enforce_reauthentication():
    if not current_user.is_authenticated:
        return None

    exempt = {
        "static",
        "logout",
        "reauth_page",
        "reauth_verify",
        "api_reauth_code",
    }
    if request.endpoint in exempt or not request.endpoint:
        return None

    active = current_session_data()
    if active and active.get("requires_reauth"):
        return redirect(url_for("reauth_page", reasons=active.get("reauth_reason") or "Suspicious activity detected"))
    return None


@app.context_processor
def inject_user_context():
    return {
        "active_session": current_session_data() if current_user.is_authenticated else None,
        "csrf_token": get_csrf_token,
    }


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard" if current_user.is_admin else "employee_dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard" if current_user.is_admin else "employee_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        limited = rate_limited_response("login", f"{client_ip()}:{username}", "Too many login attempts.")
        if limited:
            return render_template("login.html", error=limited), 429

        user_data = db.verify_user(username, request.form.get("password", ""))
        if not user_data:
            return render_template("login.html", error="Invalid credentials")

        clear_rate_limit("login", f"{client_ip()}:{username}")
        csrf_token = get_csrf_token()
        session.clear()
        session["_csrf_token"] = csrf_token
        session.permanent = True
        session["pending_user"] = tuple(user_data)
        session["pending_device_fingerprint"] = request.form.get("device_fingerprint", "")
        session["otp_context"] = "login"
        return redirect(url_for("mfa_verify"))

    return render_template("login.html")

@app.route("/api/users/<int:user_id>/delete-permanent", methods=["POST"])
@login_required
@admin_required
def delete_user_permanent(user_id):
    if user_id == current_user.id:
        return jsonify({"error": "You cannot delete your own account while signed in"}), 400
        
    username = db.hard_delete_user(user_id)
    if not username:
        return jsonify({"error": "User not found"}), 404
        
    db.log_security_event(
        current_user.id, 
        "user_deleted_permanent", 
        f"Permanently deleted user {username} and all logs", 
        "high"
    )
    return jsonify({"message": f"User {username} and all associated logs permanently deleted"})

@app.route("/mfa-verify", methods=["GET", "POST"])
def mfa_verify():
    if "pending_user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        pending_user = session.get("pending_user") or ()
        username = pending_user[1] if len(pending_user) > 1 else "unknown"
        limited = rate_limited_response("mfa", f"{client_ip()}:{username}", "Too many MFA attempts.")
        if limited:
            return render_template("mfa_verify.html", error=limited), 429
        if not verify_otp("login", request.form.get("otp", "")):
            return render_template("mfa_verify.html", error="Invalid or expired OTP")

        clear_rate_limit("mfa", f"{client_ip()}:{username}")
        user = User(*session.pop("pending_user"))
        raw_fingerprint = session.pop("pending_device_fingerprint", "")
        session.pop("otp_code", None)
        session.pop("otp_expires_at", None)
        session.pop("otp_context", None)
        login_user(user)

        user_agent = request.headers.get("User-Agent", "")
        fingerprint_hash = detector.browser_fingerprint(raw_fingerprint, user_agent)
        location = detector.geo.lookup(request.remote_addr or "127.0.0.1")
        session_id = db.create_session(
            {
                "user_id": user.id,
                "ip": request.remote_addr or "127.0.0.1",
                "user_agent": user_agent,
                "device_fingerprint": fingerprint_hash,
                "location": f"{location['city']}, {location['country']}",
                "login_time": datetime.now().isoformat(),
            }
        )
        session["active_session_id"] = session_id
        db.log_security_event(user.id, "mfa_verified", f"{user.role.title()} login completed with MFA", "info")
        return redirect(url_for("dashboard" if user.is_admin else "employee_dashboard"))

    pending_user = session.get("pending_user")
    try:
        delivery = issue_mfa_code(User(*pending_user), "login")
    except MFAProviderError as exc:
        session.pop("pending_user", None)
        session.pop("pending_device_fingerprint", None)
        db.log_security_event(None, "mfa_delivery_failed", str(exc), "high")
        return render_template("login.html", error="MFA delivery is not configured. Contact an administrator."), 503
    return render_template("mfa_verify.html", delivery=delivery)


@app.route("/logout")
@login_required
def logout():
    db.end_session(current_user.id, session.get("active_session_id"))
    db.log_security_event(current_user.id, "logout", "User signed out", "info")
    logout_user()
    session.clear()
    return redirect(url_for("login"))


def generate_otp(context):
    otp = f"{secrets.randbelow(1000000):06d}"
    session["otp_code"] = otp
    session["otp_context"] = context
    session["otp_expires_at"] = (datetime.now() + timedelta(minutes=5)).isoformat()
    return otp


def issue_mfa_code(user, context):
    otp = generate_otp(context)
    return mfa_provider.deliver_code(user, otp, context)


@app.route("/employee")
@login_required
def employee_dashboard():
    if current_user.is_admin:
        return redirect(url_for("dashboard"))
    summary = db.get_employee_summary(current_user.id)
    sessions = db.get_active_sessions(current_user.id)
    events = db.get_recent_security_events(current_user.id, limit=8)
    anomalies = db.get_anomalies(current_user.id, limit=5)
    return render_template("employee_dashboard.html", summary=summary, sessions=sessions, events=events, anomalies=anomalies)


@app.route("/dashboard")
@admin_required
def dashboard():
    stats = db.get_dashboard_stats()
    anomalies = db.get_anomalies(limit=8)
    return render_template("dashboard.html", stats=stats, anomalies=anomalies)


@app.route("/sessions")
@admin_required
def sessions_page():
    return render_template("sessions.html", sessions=db.get_active_sessions())


@app.route("/anomalies")
@admin_required
def anomalies_page():
    return render_template("anomalies.html", anomalies=db.get_anomalies())


@app.route("/sim-swap")
@admin_required
def sim_swap():
    return render_template("sim_swap.html", events=db.get_sim_swap_events())


@app.route("/settings", methods=["GET", "POST"])
@admin_required
def settings():
    policy = db.get_detection_settings()
    if request.method == "POST":
        try:
            monitor_min = int(request.form.get("monitor_min", policy["monitor_min"]))
            step_up_min = int(request.form.get("step_up_min", policy["step_up_min"]))
            block_min = int(request.form.get("block_min", policy["block_min"]))
        except ValueError:
            flash("Thresholds must be whole numbers.", "danger")
            return render_template("settings.html", settings=policy)

        if not (0 <= monitor_min < step_up_min < block_min <= 100):
            flash("Use ascending thresholds between 0 and 100.", "danger")
            return render_template("settings.html", settings=policy)

        rule_names = policy["rules"].keys()
        updated = {
            "monitor_min": monitor_min,
            "step_up_min": step_up_min,
            "block_min": block_min,
            "rules": {name: request.form.get(f"rule_{name}") == "on" for name in rule_names},
        }
        db.update_detection_settings(updated)
        detector.rules_engine.enabled_rules = updated["rules"]
        db.log_security_event(current_user.id, "settings_updated", "Detection policy updated", "info")
        flash("Detection policy saved.", "success")
        return redirect(url_for("settings"))

    return render_template("settings.html", settings=policy)


@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin_dashboard():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        role = normalize_role(request.form.get("role", "employee"))
        department = request.form.get("department", "Engineering").strip() or "Engineering"
        mfa_method = request.form.get("mfa_method", "Authenticator App")

        password_error = password_policy_error(password)
        if not username or not password:
            flash("Username and password are required.", "danger")
        elif password_error:
            flash(password_error, "danger")
        else:
            user_id, error = db.create_user(username, email, phone, password, role, department, mfa_method)
            if error:
                flash(error, "danger")
            else:
                db.log_security_event(current_user.id, "user_created", f"Created {role} account {username}", "info")
                db.log_security_event(user_id, "account_created", "Account created by security administrator", "info")
                flash(f"User {username} created.", "success")
                return redirect(url_for("admin_dashboard"))

    stats = {
        "total_users": db.count_users(),
        "blocked_sessions": db.count_blocked_sessions(),
        "high_risk_users": db.count_high_risk_users(),
        "safe_users": db.count_safe_users(),
    }
    return render_template("admin_dashboard.html", stats=stats, users=db.get_all_users_risk())


@app.route("/reauth", methods=["GET"])
@login_required
def reauth_page():
    reasons = request.args.get("reasons", "Suspicious activity detected").split(",")
    try:
        delivery = issue_mfa_code(current_user, "reauth")
    except MFAProviderError as exc:
        db.log_security_event(current_user.id, "mfa_delivery_failed", str(exc), "high")
        return render_template("reauth.html", reasons=reasons, error="MFA delivery is not configured. Contact an administrator."), 503
    return render_template("reauth.html", reasons=reasons, delivery=delivery)


@app.route("/reauth-verify", methods=["POST"])
@login_required
def reauth_verify():
    password = request.form.get("password", "")
    mfa_code = request.form.get("mfa_code", "")
    active = current_session_data()
    if not active:
        flash("No active session found.", "danger")
        return redirect(url_for("logout"))

    limited = rate_limited_response("reauth", f"{client_ip()}:{current_user.id}", "Too many verification attempts.")
    if limited:
        return render_template("reauth.html", reasons=[active.get("reauth_reason") or "Suspicious activity detected"], error=limited), 429

    user = db.verify_user(current_user.username, password)
    if user and verify_otp("reauth", mfa_code):
        clear_rate_limit("reauth", f"{client_ip()}:{current_user.id}")
        db.clear_reauth(current_user.id, active["id"])
        session.pop("otp_code", None)
        session.pop("otp_context", None)
        session.pop("otp_expires_at", None)
        db.log_security_event(current_user.id, "reauth_success", "User completed step-up authentication", "info")
        flash("Identity verified. Session restored.", "success")
        return redirect(url_for("dashboard" if current_user.is_admin else "employee_dashboard"))

    db.log_security_event(current_user.id, "reauth_failed", "Failed step-up authentication attempt", "high")
    return render_template("reauth.html", reasons=[active.get("reauth_reason") or "Suspicious activity detected"], error="Verification failed")


@app.route("/api/evaluate-session", methods=["POST"])
@login_required
def evaluate_session():
    payload = request.get_json(silent=True) or {}
    active = current_session_data()
    if not active:
        return jsonify({"error": "No active session"}), 400

    features = detector.extract_features(active, request, payload)
    policy = db.get_detection_settings()
    result = detector.evaluate(features, policy)
    reason = ", ".join(rule["name"] for rule in result["triggered_rules"]) or "No anomaly"
    db.update_session_risk(active["id"], result["risk_score"], result["recommendation"], reason)

    if result["risk_score"] >= policy["monitor_min"]:
        anomaly_type = result["triggered_rules"][0]["name"] if result["triggered_rules"] else "unknown"
        db.log_anomaly(
            {
                "user_id": current_user.id,
                "session_id": active["id"],
                "risk_score": result["risk_score"],
                "anomaly_type": anomaly_type,
                "details": json.dumps(result),
                "timestamp": datetime.now().isoformat(),
            }
        )
        severity = "critical" if result["risk_score"] >= 80 else "high" if result["risk_score"] >= 60 else "medium"
        db.log_security_event(current_user.id, "anomaly_detected", f"{anomaly_type} scored {result['risk_score']}%", severity)

    result["reauth_required"] = result["recommendation"] in ("step_up_auth", "block_session")
    result["redirect"] = url_for("reauth_page", reasons=reason) if result["reauth_required"] else None
    return jsonify(result)


@app.route("/api/check-sim-swap", methods=["POST"])
@admin_required
def check_sim_swap():
    data = request.get_json(silent=True) or {}
    user_id = int(data.get("user_id") or current_user.id)
    policy = db.get_detection_settings()
    indicators = detector.check_sim_swap_indicators(user_id, data, policy)
    db.log_sim_swap_event({**data, "user_id": user_id, "risk_score": indicators["risk_score"], "signals": indicators["signals"]})
    if indicators["risk_score"] >= policy["monitor_min"]:
        db.log_anomaly(
            {
                "user_id": user_id,
                "session_id": None,
                "risk_score": indicators["risk_score"],
                "anomaly_type": "sim_swap",
                "details": json.dumps(indicators),
                "timestamp": datetime.now().isoformat(),
            }
        )
        if indicators["is_compromised"]:
            db.force_reauth(user_id, "Possible SIM swap detected")
        db.log_security_event(user_id, "sim_swap_signal", f"SIM swap score {indicators['risk_score']}%", "high")
    return jsonify(indicators)


@app.route("/api/stats/realtime")
@admin_required
def realtime_stats():
    stats = db.get_dashboard_stats()
    stats.update(
        {
            "risk_score_history": db.get_risk_score_history(),
            "attack_types": db.get_attack_type_distribution(),
            "geo_data": db.get_geo_distribution(),
            "recent_anomalies": db.get_anomalies(limit=8),
        }
    )
    return jsonify(stats)


@app.route("/api/simulate-attack", methods=["POST"])
@admin_required
def simulate_attack():
    data = request.get_json(silent=True) or {}
    if data.get("user_id"):
        target_user_id = int(data["user_id"])
    else:
        employees = db.get_all_users_risk()
        active_employee = next((user for user in employees if user["active_sessions"]), employees[0] if employees else None)
        if not active_employee:
            return jsonify({"error": "No employee target available"}), 400
        target_user_id = int(active_employee["id"])

    active = db.get_session_data(target_user_id)
    if not active:
        demo_location = detector.geo.lookup("192.168.1.1")
        db.create_session(
            {
                "user_id": target_user_id,
                "ip": "192.168.1.1",
                "user_agent": "Mozilla/5.0 Enterprise Managed Chrome",
                "device_fingerprint": detector.browser_fingerprint("demo-managed-device", "Chrome"),
                "location": f"{demo_location['city']}, {demo_location['country']}",
                "login_time": datetime.now().isoformat(),
            }
        )
        active = db.get_session_data(target_user_id)

    attack_type = data.get("type", "session_hijacking")
    risk_score = int(data.get("risk", 85))
    description = data.get("description", "Simulated post-authentication anomaly")
    db.update_session_risk(active["id"], risk_score, "block_session" if risk_score >= 80 else "step_up_auth", attack_type)
    db.log_anomaly(
        {
            "user_id": target_user_id,
            "session_id": active["id"],
            "risk_score": risk_score,
            "anomaly_type": attack_type,
            "details": json.dumps({"description": description, "simulated": True}),
            "timestamp": datetime.now().isoformat(),
        }
    )
    db.log_security_event(target_user_id, "simulated_attack", description, "critical" if risk_score >= 80 else "high")
    return jsonify({"status": "success", "message": f"Simulated {attack_type} at {risk_score}% risk", "risk_score": risk_score})


@app.route("/api/anomalies/recent")
@admin_required
def recent_anomalies():
    return jsonify(db.get_anomalies(limit=8))


@app.route("/api/anomalies/<int:anomaly_id>/resolve", methods=["POST"])
@admin_required
def resolve_anomaly(anomaly_id):
    if not db.update_anomaly_status(anomaly_id, "resolved"):
        return jsonify({"error": "Anomaly not found"}), 404
    db.log_security_event(current_user.id, "anomaly_resolved", f"Resolved anomaly {anomaly_id}", "info")
    return jsonify({"message": "Anomaly resolved"})


@app.route("/api/anomalies/<int:anomaly_id>/false-positive", methods=["POST"])
@admin_required
def false_positive_anomaly(anomaly_id):
    if not db.update_anomaly_status(anomaly_id, "false_positive"):
        return jsonify({"error": "Anomaly not found"}), 404
    db.log_security_event(current_user.id, "false_positive", f"Marked anomaly {anomaly_id} as false positive", "info")
    return jsonify({"message": "Anomaly marked as false positive"})


@app.route("/api/force-reauth", methods=["POST"])
@admin_required
def force_reauth():
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    if user_id == "all":
        for user in db.get_all_users_risk():
            if user["risk_score"] >= 60:
                db.force_reauth(user["id"], "Admin requested verification")
        db.log_security_event(current_user.id, "forced_reauth", "Forced re-authentication for all high-risk users", "high")
        return jsonify({"message": "Re-authentication triggered for high-risk users"})

    db.force_reauth(int(user_id), "Admin requested verification")
    db.log_security_event(int(user_id), "forced_reauth", f"Admin {current_user.username} forced re-authentication", "high")
    return jsonify({"message": "Re-authentication triggered successfully"})


@app.route("/api/security-events")
@admin_required
def security_events():
    return jsonify(db.get_security_events())


@app.route("/api/users/<int:user_id>/resolve-issues", methods=["POST"])
@admin_required
def resolve_user_issues(user_id):
    if not db.get_user(user_id):
        return jsonify({"error": "User not found"}), 404
    result = db.resolve_user_issues(user_id)
    db.log_security_event(user_id, "issues_resolved", f"Admin {current_user.username} cleared active risk and open anomalies", "info")
    return jsonify({"message": "User issues resolved", **result})


@app.route("/api/users/<int:user_id>/edit", methods=["POST"])
@admin_required
def edit_user(user_id):
    data = request.get_json(silent=True) or {}
    role = normalize_role(data.get("role", "employee"))
    if user_id == int(current_user.id) and role != "admin":
        return jsonify({"error": "You cannot remove your own admin role while signed in"}), 400
    username = db.update_user(
        user_id,
        (data.get("email") or "").strip(),
        (data.get("phone") or "").strip(),
        role,
        (data.get("department") or "Engineering").strip() or "Engineering",
        data.get("mfa_method") or "Authenticator App",
    )
    if not username:
        return jsonify({"error": "User not found"}), 404
    db.log_security_event(current_user.id, "user_updated", f"Updated account {username}", "info")
    return jsonify({"message": f"User {username} updated"})


@app.route("/api/users/<int:user_id>/reset-password", methods=["POST"])
@admin_required
def reset_user_password(user_id):
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    password_error = password_policy_error(password)
    if password_error:
        return jsonify({"error": password_error}), 400
    username = db.reset_user_password(user_id, password)
    if not username:
        return jsonify({"error": "User not found"}), 404
    db.log_security_event(current_user.id, "password_reset", f"Reset password for {username}; active sessions were terminated", "high")
    db.log_security_event(user_id, "password_reset", "Password was reset by security administrator", "high")
    return jsonify({"message": f"Password reset for {username}"})


@app.route("/api/users/<int:user_id>/reactivate", methods=["POST"])
@admin_required
def reactivate_user(user_id):
    username = db.reactivate_user(user_id)
    if not username:
        return jsonify({"error": "Disabled user not found"}), 404
    db.log_security_event(current_user.id, "user_reactivated", f"Reactivated user account {username}", "high")
    return jsonify({"message": f"User {username} reactivated"})


@app.route("/api/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    if user_id == int(current_user.id):
        return jsonify({"error": "You cannot deactivate your own account while signed in"}), 400
    username = db.deactivate_user(user_id)
    if not username:
        return jsonify({"error": "User not found"}), 404
    db.log_security_event(current_user.id, "user_deactivated", f"Deactivated user account {username}", "high")
    return jsonify({"message": f"User {username} deactivated"})


@app.route("/api/sessions/<int:session_id>/terminate", methods=["POST"])
@login_required
def terminate_session(session_id):
    allow_any = current_user.is_admin
    target = db.get_session_by_id(session_id)
    if not target:
        return jsonify({"error": "Session not found"}), 404
    if not allow_any and target["user_id"] != int(current_user.id):
        return jsonify({"error": "Forbidden"}), 403
    is_current_session = target["user_id"] == int(current_user.id) and session_id == session.get("active_session_id")
    if not db.terminate_session(session_id, current_user.id, allow_any=allow_any):
        return jsonify({"error": "Session not found"}), 404
    db.log_security_event(target["user_id"], "session_terminated", f"Session {session_id} terminated", "high")
    if is_current_session:
        logout_user()
        session.clear()
        return jsonify({"message": "Current session terminated. Please sign in again.", "logout": True, "redirect": url_for("login")})
    return jsonify({"message": "Session terminated successfully"})


@app.route("/api/my/security-events")
@login_required
def my_security_events():
    return jsonify(db.get_recent_security_events(current_user.id, limit=10))


@app.errorhandler(403)
def forbidden(error):
    return render_template("error.html", code=403, title="Forbidden", message="You do not have permission to access this page."), 403


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", code=404, title="Not found", message="The page you requested does not exist."), 404


@app.errorhandler(500)
def server_error(error):
    return render_template("error.html", code=500, title="Server error", message="Something went wrong while processing the request."), 500


if __name__ == "__main__":
    db.init_db()
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug, host=os.environ.get("MFA_GUARD_HOST", "127.0.0.1"), port=int(os.environ.get("MFA_GUARD_PORT", "5000")))

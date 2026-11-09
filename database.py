import hashlib
import json
import sqlite3
from datetime import datetime

from werkzeug.security import check_password_hash, generate_password_hash


class Database:
    def __init__(self, db_path="mfa_security.db"):
        self.db_path = db_path

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT,
                phone TEXT,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'employee',
                department TEXT DEFAULT 'Engineering',
                mfa_method TEXT DEFAULT 'Authenticator App',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                risk_profile TEXT DEFAULT 'standard',
                status TEXT DEFAULT 'active',
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT,
                ip_address TEXT,
                user_agent TEXT,
                device_fingerprint TEXT,
                location TEXT,
                login_time TIMESTAMP,
                last_activity TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                risk_score REAL DEFAULT 0,
                requires_reauth BOOLEAN DEFAULT 0,
                blocked BOOLEAN DEFAULT 0,
                reauth_reason TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS request_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                user_id INTEGER,
                ip_address TEXT,
                endpoint TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                device_hash TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions (id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                session_id INTEGER,
                risk_score REAL,
                anomaly_type TEXT,
                details TEXT,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'open',
                severity TEXT DEFAULT 'medium',
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (session_id) REFERENCES sessions (id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sim_swap_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                old_carrier TEXT,
                new_carrier TEXT,
                old_imsi TEXT,
                new_imsi TEXT,
                risk_score REAL,
                signals_detected TEXT,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'open',
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                event_type TEXT,
                details TEXT,
                severity TEXT DEFAULT 'info',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS detection_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        self._migrate_columns(cursor)
        self._seed_users(cursor)
        self._seed_detection_settings(cursor)
        conn.commit()
        conn.close()

    def _migrate_columns(self, cursor):
        additions = {
            "users": {
                "role": "TEXT NOT NULL DEFAULT 'employee'",
                "department": "TEXT DEFAULT 'Engineering'",
                "mfa_method": "TEXT DEFAULT 'Authenticator App'",
                "status": "TEXT DEFAULT 'active'",
                "updated_at": "TIMESTAMP",
            },
            "sessions": {
                "requires_reauth": "BOOLEAN DEFAULT 0",
                "blocked": "BOOLEAN DEFAULT 0",
                "reauth_reason": "TEXT",
            },
            "anomalies": {"severity": "TEXT DEFAULT 'medium'"},
            "sim_swap_events": {"status": "TEXT DEFAULT 'open'"},
            "security_events": {"severity": "TEXT DEFAULT 'info'"},
        }
        for table, columns in additions.items():
            existing = {row["name"] for row in cursor.execute(f"PRAGMA table_info({table})")}
            for column, definition in columns.items():
                if column not in existing:
                    cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
                    if column == "updated_at":
                        cursor.execute(
                            f"UPDATE {table} SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL"
                        )

    def _seed_users(self, cursor):
        demo_users = [
            ("admin", "admin@company.com", "+15550000001", "admin123", "admin", "Security Operations", "Authenticator App"),
            ("alice", "alice@company.com", "+15550000002", "pass123", "employee", "Engineering", "Authenticator App"),
            ("bob", "bob@company.com", "+15550000003", "pass123", "employee", "Finance", "SMS OTP"),
            ("charlie", "charlie@company.com", "+15550000004", "pass123", "employee", "Sales", "Authenticator App"),
        ]
        for username, email, phone, password, role, department, mfa_method in demo_users:
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                cursor.execute(
                    "UPDATE users SET role = ?, department = ?, mfa_method = ? WHERE username = ?",
                    (role, department, mfa_method, username),
                )
                continue
            cursor.execute(
                """
                INSERT INTO users (username, email, phone, password_hash, role, department, mfa_method, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
                """,
                (username, email, phone, generate_password_hash(password), role, department, mfa_method),
            )

    def _seed_detection_settings(self, cursor):
        defaults = self.default_detection_settings()
        for key, value in defaults.items():
            cursor.execute(
                "INSERT OR IGNORE INTO detection_settings (key, value) VALUES (?, ?)",
                (key, json.dumps(value)),
            )

    def default_detection_settings(self):
        return {
            "monitor_min": 30,
            "step_up_min": 60,
            "block_min": 80,
            "rules": {
                "impossible_travel": True,
                "device_mismatch": True,
                "user_agent_changed": True,
                "unusual_time": True,
                "vpn_tor_datacenter": True,
                "rapid_requests": True,
                "sim_swap": True,
            },
        }

    def get_detection_settings(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM detection_settings")
        settings = self.default_detection_settings()
        for row in cursor.fetchall():
            try:
                settings[row["key"]] = json.loads(row["value"])
            except (TypeError, json.JSONDecodeError):
                continue
        conn.close()
        settings["rules"] = {**self.default_detection_settings()["rules"], **settings.get("rules", {})}
        return settings

    def update_detection_settings(self, settings):
        conn = self.get_connection()
        cursor = conn.cursor()
        for key, value in settings.items():
            cursor.execute(
                """
                INSERT INTO detection_settings (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                """,
                (key, json.dumps(value), datetime.now().isoformat()),
            )
        conn.commit()
        conn.close()

    def get_user(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, email, phone, role, department, mfa_method FROM users WHERE id = ? AND status = 'active'",
            (user_id,),
        )
        user = cursor.fetchone()
        conn.close()
        return user

    def create_user(self, username, email, phone, password, role="employee", department="Engineering", mfa_method="Authenticator App"):
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO users (username, email, phone, password_hash, role, department, mfa_method, status, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?)
                """,
                (username, email, phone, generate_password_hash(password), role, department, mfa_method, datetime.now().isoformat()),
            )
            user_id = cursor.lastrowid
            conn.commit()
            return user_id, None
        except sqlite3.IntegrityError:
            return None, "Username already exists"
        finally:
            conn.close()

    def verify_user(self, username, password):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, username, email, phone, role, department, mfa_method, password_hash
            FROM users
            WHERE username = ? AND status = 'active'
            """,
            (username,),
        )
        user = cursor.fetchone()
        conn.close()
        if not user:
            return None
        stored_hash = user["password_hash"]
        if stored_hash.startswith(("pbkdf2:", "scrypt:")):
            valid = check_password_hash(stored_hash, password)
        else:
            valid = hashlib.sha256(password.encode()).hexdigest() == stored_hash
        return tuple(user[key] for key in ("id", "username", "email", "phone", "role", "department", "mfa_method")) if valid else None

    def hard_delete_user(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            return None

        username = user["username"]
        cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM request_logs WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM anomalies WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM sim_swap_events WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM security_events WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        return username

    def create_session(self, session_info):
        conn = self.get_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute(
            """
            INSERT INTO sessions (user_id, ip_address, user_agent, device_fingerprint, location, login_time, last_activity)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_info["user_id"],
                session_info["ip"],
                session_info["user_agent"],
                session_info["device_fingerprint"],
                session_info.get("location", "Localhost"),
                session_info.get("login_time", now),
                now,
            ),
        )
        session_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return session_id

    def end_session(self, user_id, session_id=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        if session_id:
            cursor.execute("UPDATE sessions SET is_active = 0 WHERE user_id = ? AND id = ?", (user_id, session_id))
        else:
            cursor.execute("UPDATE sessions SET is_active = 0 WHERE user_id = ? AND is_active = 1", (user_id,))
        conn.commit()
        conn.close()

    def get_session_by_id(self, session_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT s.*, u.username, u.role, u.email
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.id = ?
            """,
            (session_id,),
        )
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_session_data(self, user_id, session_id=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        if session_id:
            cursor.execute("SELECT * FROM sessions WHERE user_id = ? AND id = ? AND is_active = 1", (user_id, session_id))
        else:
            cursor.execute(
                "SELECT * FROM sessions WHERE user_id = ? AND is_active = 1 ORDER BY login_time DESC LIMIT 1",
                (user_id,),
            )
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def update_session_risk(self, session_id, risk_score, recommendation, reason):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE sessions
            SET risk_score = ?, requires_reauth = ?, blocked = ?, reauth_reason = ?, last_activity = ?
            WHERE id = ?
            """,
            (
                risk_score,
                int(recommendation in ("step_up_auth", "block_session")),
                int(recommendation == "block_session"),
                reason,
                datetime.now().isoformat(),
                session_id,
            ),
        )
        conn.commit()
        conn.close()

    def clear_reauth(self, user_id, session_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE sessions
            SET risk_score = 0, requires_reauth = 0, blocked = 0, reauth_reason = NULL, last_activity = ?
            WHERE user_id = ? AND id = ?
            """,
            (datetime.now().isoformat(), user_id, session_id),
        )
        conn.commit()
        conn.close()

    def get_active_sessions(self, user_id=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        query = """
            SELECT s.*, u.username, u.email, u.department, u.role
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.is_active = 1
        """
        params = []
        if user_id:
            query += " AND s.user_id = ?"
            params.append(user_id)
        query += " ORDER BY s.risk_score DESC, s.last_activity DESC"
        cursor.execute(query, params)
        sessions = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return sessions

    def get_employee_summary(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM sessions WHERE user_id = ? AND is_active = 1", (user_id,))
        active_sessions = cursor.fetchone()[0]
        cursor.execute("SELECT MAX(risk_score) FROM sessions WHERE user_id = ? AND is_active = 1", (user_id,))
        risk_score = cursor.fetchone()[0] or 0
        cursor.execute("SELECT COUNT(*) FROM anomalies WHERE user_id = ? AND status = 'open'", (user_id,))
        open_anomalies = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM sessions WHERE user_id = ? AND requires_reauth = 1 AND is_active = 1", (user_id,))
        reauth_required = cursor.fetchone()[0] > 0
        conn.close()
        return {
            "active_sessions": active_sessions,
            "risk_score": round(risk_score, 2),
            "open_anomalies": open_anomalies,
            "reauth_required": reauth_required,
        }

    def get_dashboard_stats(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        stats = {}
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'employee' AND status = 'active'")
        stats["total_users"] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM sessions WHERE is_active = 1")
        stats["active_sessions"] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM anomalies WHERE date(detected_at) = date('now')")
        stats["anomalies_today"] = cursor.fetchone()[0]
        cursor.execute("SELECT AVG(risk_score) FROM sessions WHERE is_active = 1")
        stats["avg_risk_score"] = round(cursor.fetchone()[0] or 0, 2)
        cursor.execute("SELECT COUNT(*) FROM sessions WHERE requires_reauth = 1 AND is_active = 1")
        stats["reauth_required"] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM sessions WHERE blocked = 1 AND is_active = 1")
        stats["blocked_sessions"] = cursor.fetchone()[0]
        conn.close()
        return stats

    def log_anomaly(self, anomaly_data):
        conn = self.get_connection()
        cursor = conn.cursor()
        anomaly_type = anomaly_data["anomaly_type"]
        if isinstance(anomaly_type, dict):
            anomaly_type = anomaly_type.get("name", "unknown")
        cursor.execute(
            """
            INSERT INTO anomalies (user_id, session_id, risk_score, anomaly_type, details, detected_at, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                anomaly_data["user_id"],
                anomaly_data["session_id"],
                anomaly_data["risk_score"],
                anomaly_type,
                anomaly_data["details"],
                anomaly_data.get("timestamp", datetime.now().isoformat()),
                self._severity(anomaly_data["risk_score"]),
            ),
        )
        conn.commit()
        conn.close()

    def update_anomaly_status(self, anomaly_id, status):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE anomalies SET status = ? WHERE id = ?", (status, anomaly_id))
        changed = cursor.rowcount
        conn.commit()
        conn.close()
        return changed > 0

    def get_anomalies(self, user_id=None, limit=50):
        conn = self.get_connection()
        cursor = conn.cursor()
        query = """
            SELECT a.*, u.username, u.email
            FROM anomalies a
            JOIN users u ON a.user_id = u.id
        """
        params = []
        if user_id:
            query += " WHERE a.user_id = ?"
            params.append(user_id)
        query += " ORDER BY a.detected_at DESC LIMIT ?"
        params.append(limit)
        cursor.execute(query, params)
        anomalies = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return anomalies

    def log_sim_swap_event(self, event_data):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO sim_swap_events
                (user_id, old_carrier, new_carrier, old_imsi, new_imsi, risk_score, signals_detected, detected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_data["user_id"],
                event_data.get("old_carrier", "Unknown"),
                event_data.get("new_carrier", "Unknown"),
                event_data.get("old_imsi", "Unknown"),
                event_data.get("new_imsi", "Unknown"),
                event_data["risk_score"],
                json.dumps(event_data.get("signals", [])),
                event_data.get("timestamp", datetime.now().isoformat()),
            ),
        )
        conn.commit()
        conn.close()

    def get_sim_swap_events(self, limit=50):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT s.*, u.username, u.phone, u.email
            FROM sim_swap_events s
            JOIN users u ON s.user_id = u.id
            ORDER BY s.detected_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        events = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return events

    def get_recent_security_events(self, user_id=None, limit=50):
        conn = self.get_connection()
        cursor = conn.cursor()
        query = """
            SELECT se.*, COALESCE(u.username, 'System') AS username
            FROM security_events se
            LEFT JOIN users u ON se.user_id = u.id
        """
        params = []
        if user_id:
            query += " WHERE se.user_id = ?"
            params.append(user_id)
        query += " ORDER BY se.timestamp DESC LIMIT ?"
        params.append(limit)
        cursor.execute(query, params)
        events = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return events

    def get_risk_score_history(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT strftime('%H:%M', detected_at) AS time, AVG(risk_score) AS avg_risk
            FROM anomalies
            WHERE date(detected_at) = date('now')
            GROUP BY strftime('%H', detected_at)
            ORDER BY time
        """)
        history = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return history

    def get_attack_type_distribution(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT anomaly_type, COUNT(*) AS count
            FROM anomalies
            GROUP BY anomaly_type
            ORDER BY count DESC
        """)
        distribution = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return distribution

    def get_geo_distribution(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COALESCE(location, 'Unknown') AS location, COUNT(*) AS count
            FROM sessions
            WHERE is_active = 1
            GROUP BY COALESCE(location, 'Unknown')
        """)
        geo_data = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return geo_data

    def count_users(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'employee' AND status = 'active'")
        count = cursor.fetchone()[0]
        conn.close()
        return count

    def count_blocked_sessions(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM sessions WHERE blocked = 1 AND is_active = 1")
        count = cursor.fetchone()[0]
        conn.close()
        return count

    def count_high_risk_users(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(DISTINCT user_id) FROM sessions WHERE risk_score >= 70 AND is_active = 1")
        count = cursor.fetchone()[0]
        conn.close()
        return count

    def count_safe_users(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*)
            FROM users u
            WHERE u.role = 'employee'
            AND u.status = 'active'
            AND NOT EXISTS (
                SELECT 1 FROM sessions s
                WHERE s.user_id = u.id AND s.is_active = 1 AND s.risk_score >= 30
            )
        """)
        count = cursor.fetchone()[0]
        conn.close()
        return count

    def get_all_users_risk(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.id, u.username, u.email, u.phone, u.role, u.department, u.mfa_method, u.status,
                   COUNT(DISTINCT s.id) AS active_sessions,
                   COUNT(DISTINCT a.id) AS anomaly_count,
                   COALESCE(MAX(s.risk_score), 0) AS risk_score,
                   COALESCE(MAX(s.requires_reauth), 0) AS requires_reauth
            FROM users u
            LEFT JOIN sessions s ON u.id = s.user_id AND s.is_active = 1
            LEFT JOIN anomalies a ON u.id = a.user_id AND a.status = 'open'
            WHERE u.role = 'employee'
            GROUP BY u.id
            ORDER BY risk_score DESC, anomaly_count DESC
        """)
        users = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return users

    def force_reauth(self, user_id, reason):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE sessions
            SET requires_reauth = 1, reauth_reason = ?, risk_score = CASE WHEN risk_score < 65 THEN 65 ELSE risk_score END
            WHERE user_id = ? AND is_active = 1
            """,
            (reason, user_id),
        )
        conn.commit()
        conn.close()

    def deactivate_user(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ? AND status = 'active'", (user_id,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            return None

        cursor.execute("UPDATE users SET status = 'disabled', updated_at = ? WHERE id = ?", (datetime.now().isoformat(), user_id))
        cursor.execute("UPDATE sessions SET is_active = 0 WHERE user_id = ?", (user_id,))
        conn.commit()
        username = user["username"]
        conn.close()
        return username

    def reactivate_user(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ? AND status = 'disabled'", (user_id,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            return None
        cursor.execute("UPDATE users SET status = 'active', updated_at = ? WHERE id = ?", (datetime.now().isoformat(), user_id))
        conn.commit()
        username = user["username"]
        conn.close()
        return username

    def update_user(self, user_id, email, phone, role, department, mfa_method):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            return None
        cursor.execute(
            """
            UPDATE users
            SET email = ?, phone = ?, role = ?, department = ?, mfa_method = ?, updated_at = ?
            WHERE id = ?
            """,
            (email, phone, role, department, mfa_method, datetime.now().isoformat(), user_id),
        )
        conn.commit()
        username = user["username"]
        conn.close()
        return username

    def reset_user_password(self, user_id, password):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            return None
        cursor.execute(
            "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
            (generate_password_hash(password), datetime.now().isoformat(), user_id),
        )
        cursor.execute("UPDATE sessions SET is_active = 0 WHERE user_id = ?", (user_id,))
        conn.commit()
        username = user["username"]
        conn.close()
        return username

    def resolve_user_issues(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE anomalies SET status = 'resolved' WHERE user_id = ? AND status = 'open'", (user_id,))
        resolved = cursor.rowcount
        cursor.execute(
            """
            UPDATE sessions
            SET risk_score = 0, requires_reauth = 0, blocked = 0, reauth_reason = NULL, last_activity = ?
            WHERE user_id = ? AND is_active = 1
            """,
            (datetime.now().isoformat(), user_id),
        )
        sessions_updated = cursor.rowcount
        conn.commit()
        conn.close()
        return {"resolved_anomalies": resolved, "sessions_updated": sessions_updated}

    def reset_risk_score(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE sessions SET risk_score = 0, requires_reauth = 0, blocked = 0, reauth_reason = NULL WHERE user_id = ?",
            (user_id,),
        )
        conn.commit()
        conn.close()

    def terminate_session(self, session_id, actor_user_id=None, allow_any=False):
        conn = self.get_connection()
        cursor = conn.cursor()
        if allow_any:
            cursor.execute("UPDATE sessions SET is_active = 0 WHERE id = ?", (session_id,))
        else:
            cursor.execute("UPDATE sessions SET is_active = 0 WHERE id = ? AND user_id = ?", (session_id, actor_user_id))
        changed = cursor.rowcount
        conn.commit()
        conn.close()
        return changed > 0

    def log_security_event(self, user_id, event_type, details, severity="info"):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO security_events (user_id, event_type, details, severity) VALUES (?, ?, ?, ?)",
            (user_id, event_type, details, severity),
        )
        conn.commit()
        conn.close()

    def get_security_events(self):
        return self.get_recent_security_events(limit=50)

    def _severity(self, score):
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 40:
            return "medium"
        return "low"
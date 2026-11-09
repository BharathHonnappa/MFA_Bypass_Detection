from datetime import datetime, timedelta

from database import Database
from detector import AnomalyDetector


db = Database()
db.init_db()
detector = AnomalyDetector()

conn = db.get_connection()
conn.execute("DELETE FROM security_events")
conn.execute("DELETE FROM sim_swap_events")
conn.execute("DELETE FROM anomalies")
conn.execute("DELETE FROM request_logs")
conn.execute("DELETE FROM sessions")
conn.commit()
conn.close()


def user_id(username):
    conn = db.get_connection()
    row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row["id"]


alice = user_id("alice")
bob = user_id("bob")
charlie = user_id("charlie")

alice_session = db.create_session(
    {
        "user_id": alice,
        "ip": "192.168.1.1",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
        "device_fingerprint": detector.browser_fingerprint("alice-office-laptop", "Chrome"),
        "location": "New York, United States",
        "login_time": (datetime.now() - timedelta(hours=2)).isoformat(),
    }
)
db.update_session_risk(alice_session, 8, "allow", None)
db.log_security_event(alice, "mfa_verified", "Alice completed MFA from office laptop", "info")

charlie_session = db.create_session(
    {
        "user_id": charlie,
        "ip": "10.0.0.1",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/121",
        "device_fingerprint": detector.browser_fingerprint("unknown-linux-host", "Firefox"),
        "location": "London, United Kingdom",
        "login_time": (datetime.now() - timedelta(minutes=18)).isoformat(),
    }
)
db.update_session_risk(charlie_session, 88, "block_session", "impossible_travel, device_mismatch")
db.log_anomaly(
    {
        "user_id": charlie,
        "session_id": charlie_session,
        "risk_score": 88,
        "anomaly_type": "impossible_travel",
        "details": '{"from":"New York","to":"London","time_diff":"18 minutes"}',
        "timestamp": datetime.now().isoformat(),
    }
)
db.log_security_event(charlie, "anomaly_detected", "Impossible travel after MFA verification", "critical")

db.log_sim_swap_event(
    {
        "user_id": bob,
        "old_carrier": "Verizon",
        "new_carrier": "Unknown MVNO",
        "old_imsi": "310410123456789",
        "new_imsi": "310260987654321",
        "risk_score": 92,
        "signals": ["carrier_changed", "imsi_changed", "new_device", "recent_password_reset"],
        "timestamp": datetime.now().isoformat(),
    }
)
db.log_anomaly(
    {
        "user_id": bob,
        "session_id": None,
        "risk_score": 92,
        "anomaly_type": "sim_swap",
        "details": '{"signals":["carrier_changed","imsi_changed","new_device"]}',
        "timestamp": datetime.now().isoformat(),
    }
)
db.log_security_event(bob, "sim_swap_signal", "Carrier and IMSI changed before new-device login", "critical")
print("Demo data loaded. Admin: admin/admin123, Employee: alice/pass123")

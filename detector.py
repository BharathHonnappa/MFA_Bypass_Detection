import hashlib
import json
from datetime import datetime

from utils.geo_ip import GeoIP


class AnomalyDetector:
    def __init__(self):
        self.geo = GeoIP()
        self.rules_engine = RulesEngine()

    def extract_features(self, session_data, request, override=None):
        override = override or {}
        current_ip = override.get("ip_address") or request.headers.get("X-Demo-IP") or request.remote_addr or "127.0.0.1"
        if current_ip == "::1":
            current_ip = "127.0.0.1"
        current_user_agent = override.get("user_agent") or request.headers.get("User-Agent", "")
        current_fingerprint = override.get("device_fingerprint") or self._fingerprint(current_user_agent)
        current_location = self.geo.lookup(current_ip)

        features = {
            "current_ip": current_ip,
            "current_user_agent": current_user_agent,
            "current_device_hash": current_fingerprint,
            "geo_location": current_location,
            "geo_velocity": 0,
            "device_changed": False,
            "user_agent_changed": False,
            "is_unusual_time": self._is_unusual_time(),
            "hour_of_day": datetime.now().hour,
            "is_vpn": self.geo.is_vpn(current_ip),
            "is_tor": self.geo.is_tor(current_ip),
            "is_datacenter": self.geo.is_datacenter(current_ip),
            "request_rate": int(override.get("request_rate", 0) or 0),
            "location_label": self._location_label(current_location),
        }

        if not session_data:
            return features

        original_ip = session_data.get("ip_address") or current_ip
        original_location = self.geo.lookup(original_ip)
        login_time = session_data.get("login_time")
        features.update(
            {
                "session_age_minutes": self._calculate_session_age(login_time),
                "ip_address": original_ip,
                "original_device_hash": session_data.get("device_fingerprint") or "",
                "original_user_agent": session_data.get("user_agent") or "",
                "original_location": original_location,
                "original_location_label": self._location_label(original_location),
            }
        )
        features["geo_velocity"] = self.geo.calculate_velocity(
            original_location["latitude"],
            original_location["longitude"],
            login_time,
            current_location["latitude"],
            current_location["longitude"],
            datetime.now().isoformat(),
        )
        features["device_changed"] = bool(features["original_device_hash"] and features["original_device_hash"] != current_fingerprint)
        features["user_agent_changed"] = bool(features["original_user_agent"] and features["original_user_agent"] != current_user_agent)
        return features

    def evaluate(self, features, settings=None):
        settings = settings or {}
        rule_results = self.rules_engine.evaluate(features, settings.get("rules", {}))
        score = min(rule_results["score"], 100)
        return {
            "risk_score": round(score, 2),
            "triggered_rules": rule_results["triggered"],
            "features": self._json_safe(features),
            "recommendation": self._get_recommendation(score, settings),
        }

    def check_sim_swap_indicators(self, user_id, data, settings=None):
        settings = settings or {}
        indicators = {"risk_score": 0, "signals": [], "details": {}}
        if not settings.get("rules", {}).get("sim_swap", True):
            indicators["details"] = {
                "user_id": user_id,
                "evaluated_at": datetime.now().isoformat(),
                "summary": "SIM swap correlation is disabled by policy.",
            }
            indicators["is_compromised"] = False
            return indicators

        if data.get("old_carrier") and data.get("new_carrier") and data.get("old_carrier") != data.get("new_carrier"):
            indicators["signals"].append("carrier_changed")
            indicators["risk_score"] += 25
        if data.get("old_imsi") and data.get("new_imsi") and data.get("old_imsi") != data.get("new_imsi"):
            indicators["signals"].append("imsi_changed")
            indicators["risk_score"] += 35
        if data.get("password_reset_recent"):
            indicators["signals"].append("recent_password_reset")
            indicators["risk_score"] += 20
        if data.get("new_device_detected"):
            indicators["signals"].append("new_device")
            indicators["risk_score"] += 20
        if float(data.get("geo_velocity", 0) or 0) > 500:
            indicators["signals"].append("impossible_travel")
            indicators["risk_score"] += 30

        indicators["risk_score"] = min(indicators["risk_score"], 100)
        indicators["is_compromised"] = indicators["risk_score"] >= 60
        indicators["details"] = {
            "user_id": user_id,
            "evaluated_at": datetime.now().isoformat(),
            "summary": "SIM risk is based on carrier/IMSI changes plus account activity after the change.",
        }
        return indicators

    def browser_fingerprint(self, raw_fingerprint, user_agent):
        if raw_fingerprint:
            try:
                parsed = json.loads(raw_fingerprint)
                stable = {
                    "language": parsed.get("language", ""),
                    "platform": parsed.get("platform", ""),
                    "screenResolution": parsed.get("screenResolution", ""),
                    "timezone": parsed.get("timezone", ""),
                    "userAgent": parsed.get("userAgent", user_agent),
                }
                return self._fingerprint(json.dumps(stable, sort_keys=True))
            except json.JSONDecodeError:
                return self._fingerprint(raw_fingerprint)
        return self._fingerprint(user_agent)

    def _fingerprint(self, value):
        return hashlib.sha256((value or "").encode()).hexdigest()

    def _calculate_session_age(self, login_time):
        if not login_time:
            return 0
        login_dt = datetime.fromisoformat(login_time)
        return (datetime.now() - login_dt).total_seconds() / 60

    def _is_unusual_time(self):
        hour = datetime.now().hour
        return hour < 6 or hour > 22

    def _location_label(self, location):
        return f"{location.get('city', 'Unknown')}, {location.get('country', 'Unknown')}"

    def _get_recommendation(self, score, settings=None):
        settings = settings or {}
        monitor_min = int(settings.get("monitor_min", 30))
        step_up_min = int(settings.get("step_up_min", 60))
        block_min = int(settings.get("block_min", 80))
        if score < monitor_min:
            return "allow"
        if score < step_up_min:
            return "monitor"
        if score < block_min:
            return "step_up_auth"
        return "block_session"

    def _json_safe(self, features):
        safe = {}
        for key, value in features.items():
            safe[key] = "infinite" if value == float("inf") else value
        return safe


class RulesEngine:
    def __init__(self):
        self.rules = [
            {
                "name": "impossible_travel",
                "condition": lambda f: f.get("geo_velocity", 0) > 800,
                "weight": 40,
                "description": "Session appears from a distant location faster than human travel allows.",
            },
            {
                "name": "device_mismatch",
                "condition": lambda f: f.get("device_changed"),
                "weight": 25,
                "description": "Browser/device fingerprint changed during an active session.",
            },
            {
                "name": "user_agent_changed",
                "condition": lambda f: f.get("user_agent_changed"),
                "weight": 15,
                "description": "User agent changed after MFA was completed.",
            },
            {
                "name": "unusual_time",
                "condition": lambda f: f.get("is_unusual_time"),
                "weight": 10,
                "description": "Access occurred outside normal working hours.",
            },
            {
                "name": "vpn_tor_datacenter",
                "condition": lambda f: f.get("is_vpn") or f.get("is_tor") or f.get("is_datacenter"),
                "weight": 25,
                "description": "Connection came from VPN, Tor, or datacenter infrastructure.",
            },
            {
                "name": "rapid_requests",
                "condition": lambda f: f.get("request_rate", 0) > 100,
                "weight": 20,
                "description": "Request rate is unusually high for a normal employee session.",
            },
        ]

    def evaluate(self, features, enabled_rules=None):
        enabled_rules = enabled_rules or {}
        score = 0
        triggered = []
        for rule in self.rules:
            if not enabled_rules.get(rule["name"], True):
                continue
            if rule["condition"](features):
                score += rule["weight"]
                triggered.append({"name": rule["name"], "description": rule["description"], "weight": rule["weight"]})
        return {"score": min(score, 100), "triggered": triggered}

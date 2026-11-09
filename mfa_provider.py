import os
import re
import smtplib
import urllib.parse
import urllib.request
import urllib.error
import json
from email.message import EmailMessage


class MFAProviderError(RuntimeError):
    pass


class MFAProvider:
    def __init__(self):
        self.dev_log_codes = os.environ.get("MFA_GUARD_DEV_LOG_OTP", "false").lower() == "true"

        self.from_email = os.environ.get("MFA_GUARD_MFA_FROM_EMAIL", "mfa-guard@example.com")
        self.smtp_host = os.environ.get("MFA_GUARD_SMTP_HOST")
        self.smtp_port = int(os.environ.get("MFA_GUARD_SMTP_PORT", "587"))
        self.smtp_username = os.environ.get("MFA_GUARD_SMTP_USERNAME")
        self.smtp_password = os.environ.get("MFA_GUARD_SMTP_PASSWORD")
        self.smtp_tls = os.environ.get("MFA_GUARD_SMTP_TLS", "true").lower() == "true"

        self.fast2sms_api_key = os.environ.get("MFA_GUARD_FAST2SMS_API_KEY")
        # "otp" = Fast2SMS's built-in OTP Message route (Dev API -> Route -> "OTP Message").
        #         No DLT template or manual approval needed -- just key + number + code.
        # "dlt" = requires a fully DLT-registered entity/sender/template (not used here).
        self.fast2sms_route = os.environ.get("MFA_GUARD_FAST2SMS_ROUTE", "otp")

    @property
    def is_configured(self):
        return bool(self.smtp_host) or bool(self.fast2sms_api_key)

    def deliver_code(self, user, code, context):
        # SMS via Fast2SMS takes priority when the user has a phone number and the
        # provider is configured -- OTP-over-SMS is the realistic channel for this
        # project's sim-swap threat model (email delivery isn't affected by a SIM swap).
        if self.fast2sms_api_key and getattr(user, "phone", None):
            try:
                self._send_sms_fast2sms(user.phone, code, context)
                print(f"\n[MFA Guard] OTP sent via Fast2SMS to {user.username} ({user.phone})\n")
                return "sms (Fast2SMS)"
            except MFAProviderError as exc:
                print(f"\n[MFA Guard] Fast2SMS delivery failed for {user.username}: {exc}\n")
                if not self.smtp_host and not self.dev_log_codes:
                    raise
                # fall through to email / dev log below instead of hard-failing login

        if self.smtp_host:
            self._send_email(user.email, code, context)
            return "email"

        if self.dev_log_codes:
            print(f"\nMFA Guard development OTP for {context} ({user.username}): {code}\n")
            return "development log"

        raise MFAProviderError("No MFA delivery provider configured.")

    def _send_sms_fast2sms(self, phone, code, context):
        digits = re.sub(r"\D", "", phone or "")
        # Fast2SMS expects a bare 10-digit Indian mobile number (no +91 / 0 prefix).
        # Strip leading zeros first so "091 91xxxxxxxxx"-style inputs also normalize.
        digits = digits.lstrip("0")
        if digits.startswith("91") and len(digits) == 12:
            digits = digits[2:]
        if len(digits) != 10:
            raise MFAProviderError(f"'{phone}' is not a valid 10-digit number for Fast2SMS delivery.")

        # OTP Message route: Fast2SMS delivers via its own pre-approved OTP template
        # ("Your OTP is {#var#}") -- variables_values just fills in the code.
        payload = {
            "route": self.fast2sms_route,
            "variables_values": code,
            "numbers": digits,
        }

        req = urllib.request.Request(
            "https://www.fast2sms.com/dev/bulkV2",
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "authorization": self.fast2sms_api_key,
                "Content-Type": "application/json",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise MFAProviderError(f"Fast2SMS request failed: HTTP {exc.code} - {detail}") from exc
        except Exception as exc:
            raise MFAProviderError(f"Fast2SMS request failed: {exc}") from exc

        if not body.get("return"):
            raise MFAProviderError(f"Fast2SMS error: {body.get('message', body)}")

    def _send_email(self, recipient, code, context):
        if not recipient:
            raise MFAProviderError("User has no email address for MFA delivery.")

        message = EmailMessage()
        message["Subject"] = "Your MFA Guard verification code"
        message["From"] = self.from_email
        message["To"] = recipient
        message.set_content(
            f"Your MFA Guard {context} verification code is {code}. "
            "It expires in 5 minutes. If you did not request this, contact security."
        )

        with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as smtp:
            if self.smtp_tls:
                smtp.starttls()
            if self.smtp_username:
                smtp.login(self.smtp_username, self.smtp_password or "")
            smtp.send_message(message)
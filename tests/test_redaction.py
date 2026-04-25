import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sniffer import redact_sensitive_data, mask_ip


def test_email_redaction():
    text = "Contact me at student@example.com"
    assert "[REDACTED_EMAIL]" in redact_sensitive_data(text)


def test_password_redaction():
    text = "password=Secret123"
    assert "password=[REDACTED]" in redact_sensitive_data(text)


def test_ip_masking():
    assert mask_ip("192.168.1.55") == "192.168.x.x"
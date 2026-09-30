"""Tests for secret scanning and redaction."""

from agent_security import redact, scan


def test_scan_finds_aws_access_key():
    findings = scan("deploy with AKIAIOSFODNN7EXAMPLE today")
    assert len(findings) == 1
    assert findings[0].kind == "aws_access_key"
    assert findings[0].match == "AKIAIOSFODNN7EXAMPLE"


def test_scan_finds_github_token():
    token = "ghp_" + "a" * 36
    findings = scan(f"token is {token} ok")
    assert [f.kind for f in findings] == ["github_token"]


def test_scan_finds_openai_key():
    key = "sk-" + "b" * 32
    findings = scan(f"key={key}")
    assert [f.kind for f in findings] == ["openai_key"]


def test_scan_finds_stripe_key():
    key = "sk_live_" + "c" * 24
    findings = scan(f"billing {key} here")
    assert [f.kind for f in findings] == ["stripe_key"]


def test_scan_finds_labeled_secret():
    findings = scan('config: password = "hunter2hunter2hunter2"')
    assert [f.kind for f in findings] == ["labeled_secret"]


def test_scan_finds_high_entropy_token():
    token = "d" * 48
    findings = scan(f"blob {token} end")
    assert [f.kind for f in findings] == ["high_entropy_token"]


def test_scan_clean_text_returns_empty():
    assert scan("hello world, nothing to see here") == []


def test_scan_orders_findings_by_position():
    text = "first AKIAIOSFODNN7EXAMPLE then " + "ghp_" + "a" * 36
    findings = scan(text)
    assert [f.kind for f in findings] == ["aws_access_key", "github_token"]
    assert findings[0].start < findings[1].start


def test_scan_does_not_double_count_overlapping_patterns():
    # The OpenAI key is also a long token; it must be reported once.
    key = "sk-" + "b" * 48
    findings = scan(key)
    assert len(findings) == 1
    assert findings[0].kind == "openai_key"


def test_finding_preview_does_not_contain_full_secret():
    (finding,) = scan("use AKIAIOSFODNN7EXAMPLE now")
    assert finding.preview != finding.match
    assert len(finding.preview) < len(finding.match)


def test_redact_replaces_all_secrets():
    text = (
        "aws AKIAIOSFODNN7EXAMPLE and github " + "ghp_" + "a" * 36
    )
    redacted = redact(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "ghp_" not in redacted
    assert "[AWS_ACCESS_KEY_REDACTED]" in redacted
    assert "[GITHUB_TOKEN_REDACTED]" in redacted


def test_redact_leaves_clean_text_untouched():
    text = "plain message with no secrets"
    assert redact(text) == text

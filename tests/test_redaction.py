"""Telemetry never carries content: secret shapes out, hashes only."""

from app import redaction


def test_scrub_removes_secret_shapes():
    dirty = (
        "key AKIAIOSFODNN7EXAMPLE token bearer abcdefghijklmnopqrstuvwx "
        "ssn 123-45-6789 mail person@example.org"
    )
    clean = redaction.scrub(dirty)
    assert "AKIA" not in clean
    assert "123-45-6789" not in clean
    assert "person@example.org" not in clean
    assert clean.count("<redacted:") == 4


def test_scrub_removes_pem_blocks():
    dirty = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----"
    assert redaction.scrub(dirty) == "<redacted:private-key>"


def test_content_ref_is_hash_not_content():
    ref = redaction.content_ref("the member asked about dues")
    assert ref.startswith("sha256:")
    assert "member" not in ref

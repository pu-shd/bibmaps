"""Tests for password hashing.

These cover the migration off passlib onto the bcrypt library directly. The
risk in that swap is silent breakage for existing accounts, so the legacy
hashes below were generated with the previous stack (passlib 1.7.4 +
bcrypt 4.0.1) and are pinned here as regression fixtures.
"""
import pytest

from app.auth import (
    BCRYPT_MAX_PASSWORD_BYTES,
    get_password_hash,
    verify_password,
)

# Generated with passlib 1.7.4 / bcrypt 4.0.1, the stack used before the
# switch to calling bcrypt directly.
LEGACY_PASSLIB_HASHES = {
    "hunter2":
        "$2b$12$Qrpseow2B/yyuOxrJwTYUe4zJ6SRA5Aee2jG7eHdHU1ytKCYXUyam",
    "correct horse battery staple":
        "$2b$12$WIV2c9dZ6tmbil88c4QQmeZParaBodAQe9Fr3Hf44GztbF/Zdw./S",
    "x" * 100:
        "$2b$12$7zou.JjgdCDhoJB3tar1pumtDZHBMOq9PbagAud2eJCoUYLeGB.6u",
}


def test_hash_and_verify_round_trip():
    """A freshly hashed password verifies against its own hash."""
    assert verify_password("s3cret-pw", get_password_hash("s3cret-pw"))


def test_verify_rejects_wrong_password():
    """The wrong password does not verify."""
    assert not verify_password("wrong-pw", get_password_hash("s3cret-pw"))


def test_hash_uses_2b_prefix_and_cost_12():
    """Cost factor and prefix match what passlib produced, so hashes stay
    interchangeable and the work factor is unchanged."""
    assert get_password_hash("s3cret-pw").startswith("$2b$12$")


def test_hashes_are_salted():
    """The same password hashes differently each time."""
    assert get_password_hash("s3cret-pw") != get_password_hash("s3cret-pw")


@pytest.mark.parametrize("password,legacy_hash", LEGACY_PASSLIB_HASHES.items())
def test_legacy_passlib_hashes_still_verify(password, legacy_hash):
    """Passwords stored by the passlib-era code still log in."""
    assert verify_password(password, legacy_hash)


@pytest.mark.parametrize("password,legacy_hash", LEGACY_PASSLIB_HASHES.items())
def test_legacy_passlib_hashes_reject_wrong_password(password, legacy_hash):
    """Legacy hashes are not permissive. The difference is prefixed rather than
    appended, since bytes past the 72-byte limit are not significant."""
    assert not verify_password("nope-" + password, legacy_hash)


def test_password_longer_than_bcrypt_limit_is_accepted():
    """bcrypt 5 raises above 72 bytes where passlib truncated; the truncation
    is now explicit, so an over-long password must still hash and verify."""
    long_password = "y" * (BCRYPT_MAX_PASSWORD_BYTES + 40)
    assert verify_password(long_password, get_password_hash(long_password))


def test_password_compared_only_on_first_72_bytes():
    """Matching passlib's behaviour: bytes past the limit are not significant."""
    hashed = get_password_hash("z" * BCRYPT_MAX_PASSWORD_BYTES)
    assert verify_password("z" * (BCRYPT_MAX_PASSWORD_BYTES + 10), hashed)


def test_multibyte_password_round_trips():
    """Truncation happens on bytes, which must not break UTF-8 passwords."""
    password = "pässwörd-🔐-" + "é" * 40
    assert verify_password(password, get_password_hash(password))


@pytest.mark.parametrize("stored", [None, ""])
def test_verify_returns_false_for_missing_hash(stored):
    """OAuth-only accounts store no password hash and must not raise."""
    assert not verify_password("anything", stored)


@pytest.mark.parametrize("stored", ["not-a-hash", "$2b$12$too-short", "plaintext"])
def test_verify_returns_false_for_malformed_hash(stored):
    """A corrupt or non-bcrypt hash fails closed rather than erroring."""
    assert not verify_password("anything", stored)

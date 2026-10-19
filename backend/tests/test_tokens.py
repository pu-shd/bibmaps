"""Tests for JWT access token creation and validation."""
import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta

from app.auth import ALGORITHM, SECRET_KEY, create_access_token, decode_token


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign(header: dict, payload: dict, key: bytes, digest) -> str:
    """Build a JWT by hand so tests don't depend on the library under test."""
    signing_input = (
        _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(payload).encode())
    )
    signature = hmac.new(key, signing_input.encode("ascii"), digest).digest()
    return signing_input + "." + _b64url(signature)


def _future_exp() -> int:
    return int((datetime.utcnow() + timedelta(minutes=5)).timestamp())


class TestTokenRoundTrip:
    def test_created_token_decodes_to_same_user(self):
        token = create_access_token({"sub": 42, "username": "alice"})
        data = decode_token(token)
        assert data is not None
        assert data.user_id == 42
        assert data.username == "alice"

    def test_token_is_string_with_three_segments(self):
        token = create_access_token({"sub": 1})
        assert isinstance(token, str)
        assert token.count(".") == 2

    def test_header_uses_configured_algorithm(self):
        token = create_access_token({"sub": 1})
        header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
        assert header["alg"] == ALGORITHM == "HS256"

    def test_hand_signed_hs256_token_is_accepted(self):
        token = _sign(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "7", "username": "bob", "exp": _future_exp()},
            SECRET_KEY.encode(),
            hashlib.sha256,
        )
        data = decode_token(token)
        assert data is not None
        assert data.user_id == 7


class TestTokenRejection:
    def test_expired_token_is_rejected(self):
        token = create_access_token({"sub": 1}, expires_delta=timedelta(seconds=-60))
        assert decode_token(token) is None

    def test_token_signed_with_other_key_is_rejected(self):
        token = _sign(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "1", "exp": _future_exp()},
            b"not-the-server-secret",
            hashlib.sha256,
        )
        assert decode_token(token) is None

    def test_alg_none_token_is_rejected(self):
        token = (
            _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
            + "."
            + _b64url(json.dumps({"sub": "1", "exp": _future_exp()}).encode())
            + "."
        )
        assert decode_token(token) is None

    def test_other_hmac_algorithm_is_rejected(self):
        token = _sign(
            {"alg": "HS512", "typ": "JWT"},
            {"sub": "1", "exp": _future_exp()},
            SECRET_KEY.encode(),
            hashlib.sha512,
        )
        assert decode_token(token) is None

    def test_tampered_payload_is_rejected(self):
        header, _, signature = create_access_token({"sub": 1}).split(".")
        forged = _b64url(json.dumps({"sub": "2", "exp": _future_exp()}).encode())
        assert decode_token(f"{header}.{forged}.{signature}") is None

    def test_missing_sub_is_rejected(self):
        token = create_access_token({"username": "nobody"})
        assert decode_token(token) is None

    def test_non_integer_sub_is_rejected(self):
        token = create_access_token({"sub": "not-a-number"})
        assert decode_token(token) is None

    def test_garbage_token_is_rejected(self):
        assert decode_token("not.a.jwt") is None
        assert decode_token("") is None

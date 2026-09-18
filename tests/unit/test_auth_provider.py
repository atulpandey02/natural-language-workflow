"""SupabaseAuthProvider verification: JWKS (production) and HS256 (legacy/dev).

The asymmetric path is exercised with a locally generated RSA keypair and an
injected signing-key resolver, so no network or live Supabase is needed.
"""

import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from nlw.auth.provider import InvalidTokenError
from nlw.auth.supabase import SupabaseAuthProvider

ISSUER = "https://proj.supabase.co/auth/v1"
AUDIENCE = "authenticated"


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _rs256_provider(key: rsa.RSAPrivateKey) -> SupabaseAuthProvider:
    resolver = SimpleNamespace(
        get_signing_key_from_jwt=lambda _token: SimpleNamespace(key=key.public_key())
    )
    return SupabaseAuthProvider(issuer=ISSUER, audience=AUDIENCE, signing_key_resolver=resolver)


def _encode_rs256(key: rsa.RSAPrivateKey, **claims: object) -> str:
    payload = {"iss": ISSUER, "aud": AUDIENCE, "exp": int(time.time()) + 300, **claims}
    return jwt.encode(payload, key, algorithm="RS256", headers={"kid": "test"})


def test_rs256_valid(rsa_key: rsa.RSAPrivateKey) -> None:
    token = _encode_rs256(rsa_key, sub="user-1", email="a@example.com")
    identity = _rs256_provider(rsa_key).verify_token(token)
    assert identity.sub == "user-1"
    assert identity.email == "a@example.com"


def test_rs256_expired(rsa_key: rsa.RSAPrivateKey) -> None:
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": int(time.time()) - 10,
        "sub": "u",
        "email": "a@x.io",
    }
    token = jwt.encode(payload, rsa_key, algorithm="RS256")
    with pytest.raises(InvalidTokenError):
        _rs256_provider(rsa_key).verify_token(token)


def test_rs256_wrong_audience(rsa_key: rsa.RSAPrivateKey) -> None:
    token = _encode_rs256(rsa_key, sub="u", email="a@x.io", aud="someone-else")
    with pytest.raises(InvalidTokenError):
        _rs256_provider(rsa_key).verify_token(token)


def test_rs256_wrong_issuer(rsa_key: rsa.RSAPrivateKey) -> None:
    token = _encode_rs256(rsa_key, sub="u", email="a@x.io", iss="https://evil/auth/v1")
    with pytest.raises(InvalidTokenError):
        _rs256_provider(rsa_key).verify_token(token)


def test_rs256_bad_signature(rsa_key: rsa.RSAPrivateKey) -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = _encode_rs256(other, sub="u", email="a@x.io")  # signed by a different key
    with pytest.raises(InvalidTokenError):
        _rs256_provider(rsa_key).verify_token(token)


def test_rs256_missing_email(rsa_key: rsa.RSAPrivateKey) -> None:
    token = _encode_rs256(rsa_key, sub="u")  # email-only V1 requires the claim
    with pytest.raises(InvalidTokenError):
        _rs256_provider(rsa_key).verify_token(token)


def test_hs256_rejected_without_secret() -> None:
    provider = SupabaseAuthProvider(issuer=ISSUER, audience=AUDIENCE)
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": int(time.time()) + 60,
        "sub": "u",
        "email": "a@x.io",
    }
    token = jwt.encode(payload, "secret", algorithm="HS256")
    with pytest.raises(InvalidTokenError):
        provider.verify_token(token)


def test_hs256_accepted_with_secret_legacy() -> None:
    secret = "dev-secret-for-tests-32bytes-min-length"
    provider = SupabaseAuthProvider(issuer=ISSUER, audience=AUDIENCE, hs256_secret=secret)
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": int(time.time()) + 60,
        "sub": "u",
        "email": "a@x.io",
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    identity = provider.verify_token(token)
    assert identity.sub == "u"

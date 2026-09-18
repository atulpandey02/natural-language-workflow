"""Supabase authentication provider.

Production target (ADR-007): asymmetric verification via JWKS (RS256/ES256).
Keys are fetched lazily and cached by PyJWT's ``PyJWKClient`` on first use — no
prewarming.

Legacy/dev only: symmetric HS256 verification with a shared secret, used solely
for local development and backward compatibility with older Supabase projects.
It is not the production design; Supabase's recommended path for legacy tokens
may instead validate against the Auth server.

Every token is checked for signature, expiry (``exp``), audience (``aud``) and
issuer (``iss``). The issuer is derived from the Supabase project URL.
"""

from typing import Protocol

import jwt
from jwt import PyJWK, PyJWKClient

from nlw.auth.provider import AuthedIdentity, InvalidTokenError
from nlw.core.config import Settings

_ASYMMETRIC_ALGORITHMS = ("RS256", "ES256")


class SigningKeyResolver(Protocol):
    """Resolves the signing key for a token (satisfied by ``PyJWKClient``)."""

    def get_signing_key_from_jwt(self, token: str) -> PyJWK: ...


class SupabaseAuthProvider:
    """Verify Supabase JWTs, preferring asymmetric JWKS verification."""

    def __init__(
        self,
        *,
        issuer: str | None,
        audience: str,
        signing_key_resolver: SigningKeyResolver | None = None,
        hs256_secret: str | None = None,
    ) -> None:
        self._issuer = issuer
        self._audience = audience
        self._resolver = signing_key_resolver
        self._hs256_secret = hs256_secret

    def verify_token(self, raw: str) -> AuthedIdentity:
        try:
            header = jwt.get_unverified_header(raw)
        except jwt.PyJWTError as exc:
            raise InvalidTokenError("malformed token") from exc

        alg = header.get("alg")
        if alg in _ASYMMETRIC_ALGORITHMS:
            signing_material = self._asymmetric_key(raw)
            algorithms = [alg]
        elif alg == "HS256":
            if not self._hs256_secret:
                raise InvalidTokenError("HS256 tokens are not accepted here")
            signing_material = self._hs256_secret
            algorithms = ["HS256"]
        else:
            raise InvalidTokenError(f"unsupported token algorithm: {alg!r}")

        claims = self._decode(raw, signing_material, algorithms)
        return self._identity(claims)

    def _asymmetric_key(self, raw: str) -> object:
        if self._resolver is None:
            raise InvalidTokenError("no JWKS configured for asymmetric verification")
        try:
            return self._resolver.get_signing_key_from_jwt(raw).key
        except jwt.PyJWTError as exc:
            raise InvalidTokenError("could not resolve signing key") from exc

    def _decode(
        self, raw: str, signing_material: object, algorithms: list[str]
    ) -> dict[str, object]:
        try:
            return jwt.decode(
                raw,
                signing_material,  # type: ignore[arg-type]
                algorithms=algorithms,
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "sub"], "verify_aud": True, "verify_iss": True},
            )
        except jwt.PyJWTError as exc:
            raise InvalidTokenError("token verification failed") from exc

    @staticmethod
    def _identity(claims: dict[str, object]) -> AuthedIdentity:
        sub = claims.get("sub")
        email = claims.get("email")
        if not isinstance(sub, str) or not sub:
            raise InvalidTokenError("token missing subject")
        if not isinstance(email, str) or not email:
            # V1 supports email-authenticated users only.
            raise InvalidTokenError("token missing email claim")
        return AuthedIdentity(sub=sub, email=email)


def build_auth_provider(settings: Settings) -> SupabaseAuthProvider:
    """Construct the provider from settings (JWKS-first; HS256 if a secret set)."""
    jwks_url = settings.effective_jwks_url
    resolver = PyJWKClient(jwks_url) if jwks_url else None
    return SupabaseAuthProvider(
        issuer=settings.effective_issuer,
        audience=settings.supabase_jwt_aud,
        signing_key_resolver=resolver,
        hs256_secret=settings.supabase_jwt_secret,
    )

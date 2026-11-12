"""KMS error types. Fixed public messages, like the rest of the system."""

from __future__ import annotations

from sentinel_vault.security.errors import AppError, AuthenticationError


class KmsAuthError(AuthenticationError):
    """Bad signature, unknown principal, clock skew, or replayed nonce."""


class KmsAccessDeniedError(AppError):
    """Also returned for keys the caller can't see, so key existence isn't revealed."""

    status_code = 403
    code = "access_denied"
    public_message = "Access denied."


class KmsNotFoundError(AppError):
    status_code = 404
    code = "not_found"
    public_message = "Not found."


class KmsInvalidCiphertextError(AppError):
    """Any decrypt failure: tampered blob, wrong context, wrong account. No detail."""

    status_code = 400
    code = "invalid_ciphertext"
    public_message = "Invalid ciphertext."


class KmsKeyUnavailableError(AppError):
    status_code = 409
    code = "key_unavailable"
    public_message = "Key is not enabled."


class KmsInvalidRequestError(AppError):
    status_code = 400
    code = "invalid_request"
    public_message = "Invalid request."

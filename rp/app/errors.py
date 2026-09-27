"""Machine-readable failure reasons (logged in auth_events and returned to the client)."""


class RPError(Exception):
    def __init__(self, reason: str, status: int = 400):
        super().__init__(reason)
        self.reason = reason
        self.status = status


def reason_from_library_error(exc: Exception, ceremony: str) -> str:
    """Map py_webauthn's exception messages to our reason codes."""
    msg = str(exc).lower()
    table = [
        ("challenge", "CHALLENGE_MISMATCH"),
        ("origin", "ORIGIN_MISMATCH"),
        ("rp id", "RPID_HASH_MISMATCH"),
        ("user was not present", "UP_NOT_SET"),
        ("user presence", "UP_NOT_SET"),
        ("sign count", "COUNTER_REGRESSION"),
        ("signature", "SIGNATURE_INVALID"),
        ("unsupported", "UNSUPPORTED_ALG"),
        ("public key alg", "UNSUPPORTED_ALG"),
        ("attestation", "ATTESTATION_INVALID"),
        ("type", "WRONG_CEREMONY_TYPE"),
    ]
    for needle, code in table:
        if needle in msg:
            return code
    return "VERIFICATION_FAILED"

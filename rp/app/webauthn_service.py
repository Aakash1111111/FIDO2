"""The ONLY module that calls the WebAuthn verification library (py_webauthn).

Standard WebAuthn functionality (class A in ARCHITECTURE.md §1): building
options and verifying attestation/assertion responses (type, challenge,
origin, RP ID hash, UP flag, algorithm, attestation, signature, counter).
Nothing here is hand-rolled cryptography.
"""
import json
from typing import List, Optional

from webauthn import (generate_authentication_options, generate_registration_options,
                      options_to_json, verify_authentication_response, verify_registration_response)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (AttestationConveyancePreference, AuthenticatorAttachment,
                                      AuthenticatorSelectionCriteria, AuthenticatorTransport,
                                      PublicKeyCredentialDescriptor, PublicKeyCredentialHint,
                                      ResidentKeyRequirement, UserVerificationRequirement)

from .config import Settings
from .errors import RPError, reason_from_library_error

ACCEPTED_ATTESTATION_FORMATS = {"none", "packed"}   # packed without x5c = self attestation


def _descriptors(cred_ids: List[bytes]):
    return [PublicKeyCredentialDescriptor(id=c, transports=[AuthenticatorTransport.USB]) for c in cred_ids]


def registration_options(s: Settings, username: str, user_handle: bytes, challenge: bytes,
                         exclude_ids: List[bytes]) -> dict:
    opts = generate_registration_options(
        rp_id=s.rp_id,
        rp_name=s.rp_name,
        user_name=username,
        user_id=user_handle,
        user_display_name=username,
        challenge=challenge,
        timeout=60000,
        attestation=AttestationConveyancePreference.DIRECT,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,   # a roaming USB key
            resident_key=ResidentKeyRequirement.DISCOURAGED,                   # token: rk=false
            user_verification=UserVerificationRequirement(s.user_verification),
        ),
        exclude_credentials=_descriptors(exclude_ids),
        supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_256],        # ES256 only
        hints=[PublicKeyCredentialHint.SECURITY_KEY],  # steer phones/PCs to the USB key, not passkeys
    )
    return json.loads(options_to_json(opts))


def authentication_options(s: Settings, challenge: bytes, allow_ids: List[bytes]) -> dict:
    opts = generate_authentication_options(
        rp_id=s.rp_id,
        challenge=challenge,
        timeout=60000,
        allow_credentials=_descriptors(allow_ids),
        user_verification=UserVerificationRequirement(s.user_verification),
    )
    out = json.loads(options_to_json(opts))
    out["hints"] = ["security-key"]
    return out


def verify_registration(s: Settings, credential: dict, challenge: bytes):
    try:
        v = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=s.rp_id,
            expected_origin=s.origins,
            require_user_presence=True,
            require_user_verification=s.user_verification == "required",
            supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_256],
        )
    except (InvalidRegistrationResponse, ValueError, KeyError, TypeError) as exc:
        raise RPError(reason_from_library_error(exc, "reg")) from exc
    fmt = v.fmt.value if hasattr(v.fmt, "value") else str(v.fmt)
    if fmt not in ACCEPTED_ATTESTATION_FORMATS:
        raise RPError("ATTESTATION_FORMAT_NOT_ACCEPTED")
    return v, fmt


def verify_authentication(s: Settings, credential: dict, challenge: bytes, public_key: bytes,
                          sign_count: int):
    try:
        return verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=s.rp_id,
            expected_origin=s.origins,
            credential_public_key=public_key,
            credential_current_sign_count=sign_count,
            require_user_verification=s.user_verification == "required",
        )
    except (InvalidAuthenticationResponse, ValueError, KeyError, TypeError) as exc:
        raise RPError(reason_from_library_error(exc, "auth")) from exc


def transports_of(credential: dict) -> Optional[str]:
    t = (credential.get("response") or {}).get("transports")
    return json.dumps(t) if isinstance(t, list) else None

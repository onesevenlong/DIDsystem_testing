"""Small metadata constructors. Raw evidence and credential signatures stay outside the MPT."""
from .encoding import sha256_hex


def artifact_record(content, reference, metadata=None):
    digest = sha256_hex(content)
    return digest, {"type": "TestingArtifact", "hash": digest,
                    "ref": reference, "meta": {} if metadata is None else metadata}


def log_record(content, reference, metadata=None):
    digest = sha256_hex(content)
    return digest, {"type": "TestingLog", "hash": digest,
                    "ref": reference, "meta": {} if metadata is None else metadata}


def revocation_record(credential_id, revocation_time, metadata=None):
    """Index by H(credential_id), not by the hash of the revocation payload.

    revocation_time is the issuer-supplied effective time. This constructor
    does not authenticate the issuer or validate the clock.
    """
    if not isinstance(credential_id, str) or not credential_id:
        raise ValueError("credential_id must be a non-empty string")
    if not isinstance(revocation_time, str) or not revocation_time:
        raise ValueError("Provide a revocation effective time, preferably UTC ISO 8601")
    digest = sha256_hex(credential_id.encode("utf-8"))
    return digest, {"type": "RevokedVC", "hash": digest,
                    "credentialIdentifier": credential_id, "revoked": True,
                    "revocationTime": revocation_time,
                    "meta": {} if metadata is None else metadata}

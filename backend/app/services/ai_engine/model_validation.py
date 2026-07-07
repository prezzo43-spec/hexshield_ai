# =============================================================================
# HexShield AI — Model Artifact Validation
# Validates deep learning model weights before loading them into memory.
# =============================================================================

import hashlib
import logging
from pathlib import Path
from typing import List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

logger = logging.getLogger(__name__)


def compute_sha256_hash(weights_path: Path) -> str:
    hasher = hashlib.sha256()
    with weights_path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _load_public_key(public_key_path: Path):
    if not public_key_path.exists():
        raise FileNotFoundError(f"Public key not found: {public_key_path}")

    public_key_data = public_key_path.read_bytes()
    return serialization.load_pem_public_key(public_key_data)


def verify_model_weights_signature(
    weights_path: Path,
    signature_path: Path,
    public_key_path: Path,
) -> bool:
    if not signature_path.exists():
        logger.warning(
            "Model weights signature file not found: %s",
            signature_path,
        )
        return False

    if not public_key_path.exists():
        logger.warning(
            "Model weights public key not found: %s",
            public_key_path,
        )
        return False

    public_key = _load_public_key(public_key_path)
    signature = signature_path.read_bytes()
    file_bytes = weights_path.read_bytes()

    try:
        public_key.verify(
            signature,
            file_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        logger.warning(
            "Model weights signature verification failed for %s",
            weights_path,
        )
        return False
    except Exception as exc:
        logger.warning(
            "Unexpected error during model weights signature verification: %s",
            exc,
        )
        return False


def is_trusted_model_weights(
    weights_path: Path,
    trusted_hashes: List[str],
    public_key_path: Optional[Path],
    signature_extension: str = ".sig",
) -> bool:
    if not weights_path.exists():
        return False

    weights_hash = compute_sha256_hash(weights_path)
    is_hash_trusted = weights_hash in trusted_hashes if trusted_hashes else False

    signature_path = weights_path.with_suffix(weights_path.suffix + signature_extension)
    is_signature_trusted = False
    if public_key_path is not None and public_key_path.exists():
        is_signature_trusted = verify_model_weights_signature(
            weights_path,
            signature_path,
            public_key_path,
        )

    if is_hash_trusted:
        logger.info(
            "Model weights hash %s is trusted according to configured allowlist.",
            weights_hash,
        )
        return True

    if public_key_path is not None and public_key_path.exists():
        if is_signature_trusted:
            logger.info(
                "Model weights signature verified successfully for %s.",
                weights_path,
            )
            return True
        logger.warning(
            "Model weights %s are not trusted by signature or hash.",
            weights_path,
        )
        return False

    if trusted_hashes:
        logger.warning(
            "Model weights hash %s not found in trusted allowlist.",
            weights_hash,
        )
        return False

    logger.warning(
        "No trusted model weights allowlist configured; deep learning model weights will not be loaded."
    )
    return False

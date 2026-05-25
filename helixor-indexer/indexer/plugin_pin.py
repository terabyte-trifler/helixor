"""
indexer/plugin_pin.py — VULN-11 mitigation #4: Geyser plugin binary pinning.

THE PRINCIPLE
-------------
The Yellowstone gRPC Geyser plugin is a shared object loaded into the
validator's process. If a malicious build is published to the plugin's
package registry (a supply-chain attack), every validator that upgrades
suddenly streams attacker-controlled data — and the signed-envelope and
RPC-cross-verify mitigations are powerless because the ENDPOINT itself
is signing forged updates.

The defence is a PIN: the deployment refuses to start the indexer
against a plugin endpoint whose binary's sha256 doesn't match a
manifest entry that is itself signed by a trusted release engineer.

THE MANIFEST
------------
A `PluginPinManifest` is a list of `PluginPin` entries. Each pin binds:

  * the plugin's exact binary sha256 (computed from the file on disk),
  * the plugin's semantic version string,
  * a 64-byte Ed25519 signature over `binary_sha256 || version`,
  * the 32-byte public key of the release engineer who signed it.

The deployment carries:

  * the manifest (JSON or in-memory),
  * a `TrustedReleaseSignerSet` — the pubkeys of release engineers
    permitted to sign manifest entries.

At startup, the indexer computes the live binary's sha256, looks up its
version in the manifest, verifies the pin's signature against a trusted
release signer, and refuses to start on any failure.

WHY IN-REPO INSTEAD OF DEFERRED-TO-CI
-------------------------------------
Reproducible builds are a CI concern. PIN VERIFICATION is a runtime
concern — the indexer must refuse to talk to a plugin whose binary
hash isn't approved, regardless of how the binary got there. The hash +
signature check is pure software, fully testable, and is the
sharp-edge gate that turns a CI artifact promise into a runtime
guarantee.

NOTE: this module does NOT execute or load the plugin. It verifies
the FILE before deployment hands it to the validator. The pure
verification surface is what is tested here; the
"this is the path of the live plugin on disk" wiring is a deployment
seam.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path


# =============================================================================
# Constants
# =============================================================================

#: Length of a sha256 digest.
SHA256_LEN = 32

#: Length of an Ed25519 signature.
SIGNATURE_LEN = 64

#: Length of an Ed25519 public key (raw).
PUBKEY_LEN = 32

#: Stream the file in chunks so we don't blow memory on a multi-megabyte
#: plugin .so.
_HASH_CHUNK = 1 << 20  # 1 MiB


# =============================================================================
# Exceptions
# =============================================================================

class PluginPinError(Exception):
    """Raised when a plugin binary fails its pin verification."""


class UntrustedReleaseSigner(PluginPinError):
    """The pin verifies, but the signer is not a trusted release engineer."""


# =============================================================================
# Types
# =============================================================================

@dataclass(frozen=True, slots=True)
class PluginPin:
    """
    A signed binding of (binary_sha256, version) -> approved.

    On the wire (JSON), bytes fields are hex-encoded. In memory, raw bytes.
    """
    version:        str
    binary_sha256:  bytes              # 32 bytes
    signer_pubkey:  bytes              # 32 bytes Ed25519 public key
    signature:      bytes              # 64 bytes Ed25519 over message()

    def __post_init__(self) -> None:
        if not self.version:
            raise ValueError("PluginPin.version must be non-empty")
        if len(self.binary_sha256) != SHA256_LEN:
            raise ValueError(
                f"PluginPin.binary_sha256 must be {SHA256_LEN} bytes, "
                f"got {len(self.binary_sha256)}"
            )
        if len(self.signer_pubkey) != PUBKEY_LEN:
            raise ValueError(
                f"PluginPin.signer_pubkey must be {PUBKEY_LEN} bytes, "
                f"got {len(self.signer_pubkey)}"
            )
        if len(self.signature) != SIGNATURE_LEN:
            raise ValueError(
                f"PluginPin.signature must be {SIGNATURE_LEN} bytes, "
                f"got {len(self.signature)}"
            )

    def message(self) -> bytes:
        """
        The bytes the signature is over. Binds the binary hash AND the
        version string, so a pin for v1.0.0 cannot be replayed as a pin
        for v1.0.1 even if the binary hash were the same.
        """
        return self.binary_sha256 + self.version.encode("utf-8")


@dataclass(frozen=True, slots=True)
class TrustedReleaseSigner:
    """A release engineer the deployment accepts pin signatures from."""
    name:       str
    public_key: bytes

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("TrustedReleaseSigner.name must be non-empty")
        if len(self.public_key) != PUBKEY_LEN:
            raise ValueError(
                f"TrustedReleaseSigner.public_key must be {PUBKEY_LEN} bytes, "
                f"got {len(self.public_key)}"
            )


class TrustedReleaseSignerSet:
    """The set of release-engineer pubkeys allowed to sign plugin pins."""

    __slots__ = ("_by_pubkey",)

    def __init__(self, signers: Iterable[TrustedReleaseSigner]) -> None:
        by_pubkey: dict[bytes, TrustedReleaseSigner] = {}
        for s in signers:
            if s.public_key in by_pubkey:
                raise ValueError(
                    f"duplicate release-signer pubkey: "
                    f"existing={by_pubkey[s.public_key].name!r}, "
                    f"new={s.name!r}"
                )
            by_pubkey[s.public_key] = s
        if not by_pubkey:
            raise ValueError(
                "TrustedReleaseSignerSet must be non-empty — refusing to "
                "construct a pin verifier that trusts no signer at all"
            )
        object.__setattr__(self, "_by_pubkey", dict(by_pubkey))

    @property
    def size(self) -> int:
        return len(self._by_pubkey)

    def is_trusted(self, public_key: bytes) -> bool:
        return public_key in self._by_pubkey

    def name_of(self, public_key: bytes) -> str:
        signer = self._by_pubkey.get(public_key)
        return signer.name if signer else "<untrusted>"


# =============================================================================
# PluginPinManifest — name -> pin
# =============================================================================

class PluginPinManifest:
    """
    An immutable mapping of plugin version -> `PluginPin`.

    Versions are keyed verbatim (no semver normalization) so the deployment
    is exact about which build is approved.
    """

    __slots__ = ("_by_version",)

    def __init__(self, pins: Iterable[PluginPin]) -> None:
        by_version: dict[str, PluginPin] = {}
        for pin in pins:
            if pin.version in by_version:
                raise ValueError(
                    f"duplicate pin for version {pin.version!r}"
                )
            by_version[pin.version] = pin
        object.__setattr__(self, "_by_version", dict(by_version))

    def get(self, version: str) -> PluginPin | None:
        return self._by_version.get(version)

    @property
    def size(self) -> int:
        return len(self._by_version)


# =============================================================================
# Hashing — stream the file
# =============================================================================

def compute_binary_sha256(path: Path | str) -> bytes:
    """sha256 of the file at `path`, streamed. Pure stdlib."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_HASH_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.digest()


# =============================================================================
# Verification — the runtime gate
# =============================================================================

def verify_plugin_binary(
    binary_path:      Path | str,
    version:          str,
    manifest:         PluginPinManifest,
    trusted_signers:  TrustedReleaseSignerSet,
) -> PluginPin:
    """
    Verify that the plugin binary at `binary_path` is approved for `version`.

    Steps (each one fails closed):

      1. Manifest must contain a pin for `version`.
      2. Computed sha256 of the binary must equal `pin.binary_sha256`.
      3. The pin signer must be in `trusted_signers`.
      4. `pin.signature` must verify against `pin.signer_pubkey` over
         `pin.message()`.

    Returns the pin on success; raises `PluginPinError` (or its
    `UntrustedReleaseSigner` subclass) on any failure. The deployment's
    bootstrap script aborts on any raise.
    """
    pin = manifest.get(version)
    if pin is None:
        raise PluginPinError(
            f"no pin in manifest for plugin version {version!r}"
        )

    actual_hash = compute_binary_sha256(binary_path)
    if actual_hash != pin.binary_sha256:
        raise PluginPinError(
            f"plugin binary hash mismatch for version {version!r}: "
            f"expected {pin.binary_sha256.hex()}, got {actual_hash.hex()}"
        )

    if not trusted_signers.is_trusted(pin.signer_pubkey):
        raise UntrustedReleaseSigner(
            f"plugin pin for version {version!r} signed by untrusted key "
            f"{pin.signer_pubkey.hex()[:16]}..."
        )

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError as exc:                       # pragma: no cover
        raise PluginPinError(
            "ed25519 verification requires the 'cryptography' package"
        ) from exc

    try:
        pub = Ed25519PublicKey.from_public_bytes(pin.signer_pubkey)
        pub.verify(pin.signature, pin.message())
    except Exception as exc:                          # noqa: BLE001
        raise PluginPinError(
            f"plugin pin signature verification failed: {exc}"
        ) from exc

    return pin


# =============================================================================
# JSON codec — manifest on disk
# =============================================================================

def manifest_from_json(text: str) -> PluginPinManifest:
    """
    Parse a JSON manifest of the form:

        {
          "pins": [
            {
              "version":       "1.2.3",
              "binary_sha256": "<64 hex chars>",
              "signer_pubkey": "<64 hex chars>",
              "signature":     "<128 hex chars>"
            },
            ...
          ]
        }

    Raises `ValueError` on malformed JSON or wrong field lengths.
    """
    raw = json.loads(text)
    if not isinstance(raw, dict) or "pins" not in raw:
        raise ValueError("manifest JSON must be an object with a 'pins' array")
    pins_raw = raw["pins"]
    if not isinstance(pins_raw, list):
        raise ValueError("manifest 'pins' must be a list")
    pins = [
        PluginPin(
            version=_required_str(p, "version"),
            binary_sha256=bytes.fromhex(_required_str(p, "binary_sha256")),
            signer_pubkey=bytes.fromhex(_required_str(p, "signer_pubkey")),
            signature=bytes.fromhex(_required_str(p, "signature")),
        )
        for p in pins_raw
    ]
    return PluginPinManifest(pins)


def manifest_to_json(manifest: PluginPinManifest) -> str:
    """Inverse of `manifest_from_json`. Used by the release-signing tool."""
    return json.dumps({
        "pins": [
            {
                "version":       pin.version,
                "binary_sha256": pin.binary_sha256.hex(),
                "signer_pubkey": pin.signer_pubkey.hex(),
                "signature":     pin.signature.hex(),
            }
            # Use a private accessor over the dict for determinism in tests.
            for pin in manifest._by_version.values()  # noqa: SLF001
        ]
    }, sort_keys=True)


def _required_str(obj: dict, key: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"manifest pin missing required string field {key!r}")
    return value


__all__ = [
    "SHA256_LEN", "SIGNATURE_LEN", "PUBKEY_LEN",
    "PluginPinError", "UntrustedReleaseSigner",
    "PluginPin",
    "TrustedReleaseSigner", "TrustedReleaseSignerSet",
    "PluginPinManifest",
    "compute_binary_sha256", "verify_plugin_binary",
    "manifest_from_json", "manifest_to_json",
]

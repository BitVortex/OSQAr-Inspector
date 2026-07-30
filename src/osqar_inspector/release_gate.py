"""Distribution integrity and public-contract release gates."""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import re
import stat
import sys
import tarfile
import unicodedata
from collections.abc import Callable
from email.parser import BytesParser
from importlib.metadata import version as installed_version
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any
from zipfile import BadZipFile, ZipFile

PACKAGE_NAME = "osqar-inspector"
POLICY_SCHEMA = "osqar.inspector.release-policy.v1"
POLICY_RESOURCE = "release-policy-v1.json"
REQUIRED_PYTHON = "<3.14,>=3.12"
LINUX_CLASSIFIER = "Operating System :: POSIX :: Linux"
REQUIRED_CONTRACT_ASSETS = frozenset(
    {
        "osqar_inspector/resources/config-v1.schema.json",
        "osqar_inspector/resources/coverage-attestation-v1.schema.json",
        "osqar_inspector/resources/coverage-map-v1.schema.json",
        "osqar_inspector/resources/defaults-v1.json",
        "osqar_inspector/resources/interoperability/signatures-v1-ed25519.json",
        "osqar_inspector/resources/interoperability/vectors.json",
        "osqar_inspector/resources/plan-v1.schema.json",
        "osqar_inspector/resources/release-policy-v1.json",
    }
)
_RESOURCE_PREFIX = "osqar_inspector/resources/"
REQUIRED_POLICY_ASSETS = frozenset(
    asset.removeprefix(_RESOURCE_PREFIX)
    for asset in REQUIRED_CONTRACT_ASSETS
    if asset != _RESOURCE_PREFIX + POLICY_RESOURCE
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class DistributionError(ValueError):
    """A built distribution does not contain the required public contracts."""


class ContractPolicyError(ValueError):
    """A public contract or support declaration violates the release policy."""


def _policy_bytes() -> bytes:
    return files("osqar_inspector").joinpath("resources", POLICY_RESOURCE).read_bytes()


def _parse_policy(content: bytes) -> dict[str, Any]:
    try:
        policy = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractPolicyError("release policy is not readable JSON") from error
    if not isinstance(policy, dict):
        raise ContractPolicyError("release policy must be a JSON object")
    return policy


def _installed_asset(relative: str) -> bytes:
    return (
        files("osqar_inspector")
        .joinpath("resources", *PurePosixPath(relative).parts)
        .read_bytes()
    )


def load_release_policy() -> dict[str, Any]:
    """Load and validate the release policy shipped by the installed package."""

    try:
        policy = _parse_policy(_policy_bytes())
        _validate_release_policy(
            policy,
            package_version=installed_version(PACKAGE_NAME),
            read_asset=_installed_asset,
        )
    except OSError as error:
        raise ContractPolicyError(
            "release policy or contract asset is unreadable"
        ) from error
    return policy


def _unique_strings(value: object, name: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise ContractPolicyError(f"{name} must be a non-empty string array")
    if value != sorted(set(value), key=str.encode):
        raise ContractPolicyError(f"{name} must be unique and bytewise sorted")
    return value


def _validate_release_policy(
    policy: dict[str, Any],
    *,
    package_version: str,
    read_asset: Callable[[str], bytes],
) -> None:
    """Validate exact package, platform, protocol, schema, and fixture declarations."""

    if set(policy) != {
        "contract_assets",
        "fixture_revision",
        "package",
        "schema",
        "support",
    }:
        raise ContractPolicyError("release policy is not a closed v1 object")
    if policy["schema"] != POLICY_SCHEMA:
        raise ContractPolicyError("unsupported release-policy schema")
    package = policy["package"]
    if not isinstance(package, dict) or set(package) != {"name", "version"}:
        raise ContractPolicyError("release policy package metadata is malformed")
    if package["name"] != PACKAGE_NAME or package["version"] != package_version:
        raise ContractPolicyError(
            "release policy package version does not match metadata"
        )
    revision = policy["fixture_revision"]
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise ContractPolicyError("fixture revision must be a positive integer")
    support = policy["support"]
    if not isinstance(support, dict) or set(support) != {
        "operating_systems",
        "process_protocols",
        "python",
        "schemas",
    }:
        raise ContractPolicyError("release support declaration is malformed")
    operating_systems = _unique_strings(
        support["operating_systems"], "operating systems"
    )
    python_versions = _unique_strings(support["python"], "Python versions")
    protocols = _unique_strings(support["process_protocols"], "process protocols")
    schemas = _unique_strings(support["schemas"], "schemas")
    if operating_systems != ["linux"]:
        raise ContractPolicyError("the advertised operating-system set must be Linux")
    if python_versions != ["3.12", "3.13"]:
        raise ContractPolicyError(
            "supported Python versions contradict the support policy"
        )
    if protocols != ["osqar-inspector-run-v1"]:
        raise ContractPolicyError(
            "supported protocol set contradicts the implementation"
        )
    if POLICY_SCHEMA not in schemas:
        raise ContractPolicyError(
            "release-policy schema is absent from supported schemas"
        )
    assets = policy["contract_assets"]
    if not isinstance(assets, dict) or set(assets) != REQUIRED_POLICY_ASSETS:
        raise ContractPolicyError(
            "contract asset bindings must name the complete required set"
        )
    if list(assets) != sorted(assets, key=str.encode):
        raise ContractPolicyError("contract asset bindings must be bytewise sorted")
    for relative, expected_digest in assets.items():
        if (
            not isinstance(relative, str)
            or PurePosixPath(relative).is_absolute()
            or ".." in PurePosixPath(relative).parts
            or not isinstance(expected_digest, str)
            or _SHA256.fullmatch(expected_digest) is None
        ):
            raise ContractPolicyError("contract asset binding is malformed")
        try:
            content = read_asset(relative)
        except (KeyError, OSError) as error:
            raise ContractPolicyError(
                f"contract asset is missing: {relative}"
            ) from error
        if hashlib.sha256(content).hexdigest() != expected_digest:
            raise ContractPolicyError(f"contract asset digest changed: {relative}")


def validate_release_policy(policy: dict[str, Any]) -> None:
    """Validate a policy against this installed package's metadata and assets."""

    _validate_release_policy(
        policy,
        package_version=installed_version(PACKAGE_NAME),
        read_asset=_installed_asset,
    )


def validate_contract_change(
    previous: dict[str, object],
    current: dict[str, object],
    *,
    contracts_changed: bool,
) -> None:
    """Require both compatibility-fixture and package-version updates."""

    if not contracts_changed:
        return
    previous_package = previous.get("package")
    current_package = current.get("package")
    if not isinstance(previous_package, dict) or not isinstance(current_package, dict):
        raise ContractPolicyError("release policy package metadata is malformed")
    if current_package.get("version") == previous_package.get("version"):
        raise ContractPolicyError("contract change requires a package version update")
    if current.get("fixture_revision") == previous.get("fixture_revision"):
        raise ContractPolicyError("contract change requires a fixture revision update")


def _validate_metadata(content: bytes) -> str:
    metadata = BytesParser().parsebytes(content)
    if metadata.get("Name") != PACKAGE_NAME:
        raise DistributionError("package metadata has the wrong name")
    package_version = metadata.get("Version")
    if not isinstance(package_version, str) or not package_version:
        raise DistributionError("package metadata has no version")
    if metadata.get("Requires-Python") != REQUIRED_PYTHON:
        raise DistributionError("package metadata has the wrong Python support range")
    if LINUX_CLASSIFIER not in metadata.get_all("Classifier", []):
        raise DistributionError("package metadata does not declare Linux support")
    return package_version


def _validate_archive_names(names: list[str], *, kind: str) -> None:
    normalized: set[str] = set()
    for name in names:
        path = PurePosixPath(name)
        key = unicodedata.normalize("NFC", name).casefold()
        if (
            not name
            or "\\" in name
            or path.is_absolute()
            or ".." in path.parts
            or path.as_posix() != name
            or key in normalized
        ):
            raise DistributionError(f"unsafe or unexpected {kind} member: {name!r}")
        normalized.add(key)


def _validate_wheel_record(
    archive: ZipFile, names: set[str], *, record_name: str
) -> None:
    try:
        rows = list(csv.reader(archive.read(record_name).decode("utf-8").splitlines()))
    except (KeyError, UnicodeDecodeError, csv.Error) as error:
        raise DistributionError("wheel RECORD is unreadable") from error
    if any(len(row) != 3 for row in rows):
        raise DistributionError("wheel RECORD is malformed")
    recorded_names = [row[0] for row in rows]
    if len(set(recorded_names)) != len(recorded_names) or set(recorded_names) != names:
        raise DistributionError("wheel RECORD does not match archive")
    for member_name, digest, size in rows:
        if member_name == record_name:
            if digest or size:
                raise DistributionError("wheel RECORD self-entry is malformed")
            continue
        content = archive.read(member_name)
        expected_digest = "sha256=" + base64.urlsafe_b64encode(
            hashlib.sha256(content).digest()
        ).rstrip(b"=").decode("ascii")
        if digest != expected_digest or size != str(len(content)):
            raise DistributionError(f"wheel RECORD mismatch: {member_name}")


def validate_wheel(path: Path) -> None:
    """Reject a wheel with incomplete assets or contradictory package metadata."""

    try:
        with ZipFile(path) as archive:
            entries = archive.infolist()
            member_names = [entry.filename for entry in entries]
            names = set(member_names)
            if len(names) != len(entries):
                raise DistributionError("wheel contains duplicate archive members")
            _validate_archive_names(member_names, kind="wheel")
            for entry in entries:
                mode = entry.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                if entry.is_dir() or file_type not in {0, stat.S_IFREG}:
                    raise DistributionError(
                        f"unsafe or unexpected wheel member: {entry.filename!r}"
                    )
            metadata_names = sorted(
                name for name in names if name.endswith(".dist-info/METADATA")
            )
            missing = sorted(REQUIRED_CONTRACT_ASSETS - names)
            if missing:
                raise DistributionError(
                    "missing required contract assets: " + ", ".join(missing)
                )
            if len(metadata_names) != 1:
                raise DistributionError("wheel must contain exactly one METADATA file")
            package_version = _validate_metadata(archive.read(metadata_names[0]))
            expected_dist_info = f"osqar_inspector-{package_version}.dist-info/METADATA"
            if metadata_names[0] != expected_dist_info:
                raise DistributionError(
                    "wheel dist-info directory does not match metadata"
                )
            dist_info_root = expected_dist_info.rsplit("/", 1)[0] + "/"
            if any(
                not name.startswith(("osqar_inspector/", dist_info_root))
                for name in names
            ):
                raise DistributionError("unsafe or unexpected wheel member")
            _validate_wheel_record(
                archive, names, record_name=dist_info_root + "RECORD"
            )
            expected_name = f"osqar_inspector-{package_version}-py3-none-any.whl"
            if path.name != expected_name:
                raise DistributionError("wheel filename does not match metadata")
            policy = _parse_policy(
                archive.read("osqar_inspector/resources/release-policy-v1.json")
            )
            _validate_release_policy(
                policy,
                package_version=package_version,
                read_asset=lambda relative: archive.read(
                    "osqar_inspector/resources/" + relative
                ),
            )
    except DistributionError:
        raise
    except ContractPolicyError as error:
        raise DistributionError(str(error)) from error
    except (BadZipFile, KeyError, OSError) as error:
        raise DistributionError(f"invalid wheel: {path}") from error


def validate_sdist(path: Path) -> None:
    """Reject an sdist with incomplete contract assets or package metadata."""

    try:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            member_names = [member.name for member in members]
            names = set(member_names)
            if len(names) != len(members):
                raise DistributionError("sdist contains duplicate archive members")
            _validate_archive_names(member_names, kind="sdist")
            if any(not member.isfile() for member in members):
                raise DistributionError("unsafe or unexpected sdist member")
            missing = sorted(
                asset
                for asset in REQUIRED_CONTRACT_ASSETS
                if not any(name.endswith("/src/" + asset) for name in names)
            )
            if missing:
                raise DistributionError(
                    "missing required contract assets: " + ", ".join(missing)
                )
            metadata_members = [
                member
                for member in members
                if member.isfile()
                and member.name.count("/") == 1
                and member.name.endswith("/PKG-INFO")
            ]
            if len(metadata_members) != 1:
                raise DistributionError(
                    "sdist must contain exactly one root PKG-INFO file"
                )
            extracted = archive.extractfile(metadata_members[0])
            if extracted is None:
                raise DistributionError("sdist metadata is unreadable")
            package_version = _validate_metadata(extracted.read())
            expected_filename = f"osqar_inspector-{package_version}.tar.gz"
            if path.name != expected_filename:
                raise DistributionError("sdist filename does not match metadata")
            root = metadata_members[0].name.rsplit("/", 1)[0]
            if root != f"osqar_inspector-{package_version}":
                raise DistributionError("sdist archive root does not match metadata")
            if any(not name.startswith(root + "/") for name in names):
                raise DistributionError("unsafe or unexpected sdist member")

            def read_asset(relative: str) -> bytes:
                member = archive.getmember(
                    f"{root}/src/osqar_inspector/resources/{relative}"
                )
                content = archive.extractfile(member)
                if content is None:
                    raise KeyError(relative)
                return content.read()

            policy = _parse_policy(read_asset(POLICY_RESOURCE))
            _validate_release_policy(
                policy,
                package_version=package_version,
                read_asset=read_asset,
            )
    except DistributionError:
        raise
    except ContractPolicyError as error:
        raise DistributionError(str(error)) from error
    except (KeyError, tarfile.TarError, OSError) as error:
        raise DistributionError(f"invalid sdist: {path}") from error


def validate_distribution(path: Path) -> None:
    """Validate one wheel or gzip-compressed source distribution."""

    if path.suffix == ".whl":
        validate_wheel(path)
    elif path.name.endswith(".tar.gz"):
        validate_sdist(path)
    else:
        raise DistributionError(f"unsupported distribution type: {path.name}")


def main(argv: list[str] | None = None) -> int:
    paths = [Path(item) for item in (sys.argv[1:] if argv is None else argv)]
    if not paths:
        print("usage: python -m osqar_inspector.release_gate DIST...", file=sys.stderr)
        return 2
    try:
        load_release_policy()
        for path in paths:
            validate_distribution(path)
    except (ContractPolicyError, DistributionError) as error:
        print(f"release gate failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

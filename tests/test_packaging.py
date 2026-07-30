from __future__ import annotations

import base64
import csv
import hashlib
import io
import stat
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

from osqar_inspector.release_gate import (
    DistributionError,
    validate_sdist,
    validate_wheel,
)


def test_wheel_fails_if_contract_assets_are_missing(tmp_path: Path) -> None:
    wheel = tmp_path / "osqar_inspector-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("osqar_inspector/__init__.py", "")
        archive.writestr(
            "osqar_inspector-0.1.0.dist-info/METADATA",
            "Metadata-Version: 2.4\nName: osqar-inspector\nVersion: 0.1.0\n",
        )

    with pytest.raises(DistributionError, match="missing required contract assets"):
        validate_wheel(wheel)


def test_built_wheel_contains_all_contract_assets(tmp_path: Path) -> None:
    checkout = Path(__file__).resolve().parents[1]
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(tmp_path)],
        cwd=checkout,
        check=True,
    )

    validate_wheel(next(tmp_path.glob("osqar_inspector-*.whl")))


def test_wheel_rejects_renamed_distribution(tmp_path: Path) -> None:
    checkout = Path(__file__).resolve().parents[1]
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(wheelhouse)],
        cwd=checkout,
        check=True,
    )
    original = next(wheelhouse.glob("osqar_inspector-*.whl"))
    renamed = tmp_path / ("renamed-" + original.name)
    renamed.write_bytes(original.read_bytes())

    with pytest.raises(
        DistributionError, match="wheel filename does not match metadata"
    ):
        validate_wheel(renamed)


def test_wheel_rejects_mismatched_dist_info_directory(tmp_path: Path) -> None:
    checkout = Path(__file__).resolve().parents[1]
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(wheelhouse)],
        cwd=checkout,
        check=True,
    )
    original = next(wheelhouse.glob("osqar_inspector-*.whl"))
    altered = tmp_path / original.name
    with (
        zipfile.ZipFile(original) as source,
        zipfile.ZipFile(altered, "w") as destination,
    ):
        for item in source.infolist():
            name = item.filename
            if name.endswith(".dist-info/METADATA"):
                name = "other-0.1.0.dist-info/METADATA"
            destination.writestr(name, source.read(item.filename))

    with pytest.raises(
        DistributionError, match="dist-info directory does not match metadata"
    ):
        validate_wheel(altered)


def test_wheel_rejects_tampered_contract_asset(tmp_path: Path) -> None:
    checkout = Path(__file__).resolve().parents[1]
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(wheelhouse)],
        cwd=checkout,
        check=True,
    )
    original = next(wheelhouse.glob("osqar_inspector-*.whl"))
    tampered = tmp_path / original.name
    target = "osqar_inspector/resources/config-v1.schema.json"
    with (
        zipfile.ZipFile(original) as source,
        zipfile.ZipFile(tampered, "w") as destination,
    ):
        for item in source.infolist():
            content = source.read(item.filename)
            if item.filename == target:
                content = b"{}"
            elif item.filename.endswith(".dist-info/RECORD"):
                rows = list(csv.reader(content.decode("utf-8").splitlines()))
                for row in rows:
                    if row[0] == target:
                        row[1] = "sha256=" + base64.urlsafe_b64encode(
                            hashlib.sha256(b"{}").digest()
                        ).rstrip(b"=").decode("ascii")
                        row[2] = "2"
                output = io.StringIO(newline="")
                csv.writer(output, lineterminator="\n").writerows(rows)
                content = output.getvalue().encode("utf-8")
            destination.writestr(item, content)

    with pytest.raises(DistributionError, match="contract asset digest changed"):
        validate_wheel(tampered)


def test_sdist_rejects_renamed_distribution(tmp_path: Path) -> None:
    checkout = Path(__file__).resolve().parents[1]
    dist = tmp_path / "dist"
    dist.mkdir()
    subprocess.run(
        ["uv", "build", "--sdist", "--out-dir", str(dist)],
        cwd=checkout,
        check=True,
    )
    original = next(dist.glob("osqar_inspector-*.tar.gz"))
    renamed = tmp_path / ("renamed-" + original.name)
    renamed.write_bytes(original.read_bytes())

    with pytest.raises(
        DistributionError, match="sdist filename does not match metadata"
    ):
        validate_sdist(renamed)


def test_sdist_rejects_mismatched_archive_root(tmp_path: Path) -> None:
    checkout = Path(__file__).resolve().parents[1]
    dist = tmp_path / "dist"
    dist.mkdir()
    subprocess.run(
        ["uv", "build", "--sdist", "--out-dir", str(dist)],
        cwd=checkout,
        check=True,
    )
    original = next(dist.glob("osqar_inspector-*.tar.gz"))
    altered = tmp_path / original.name
    with (
        tarfile.open(original, "r:gz") as source,
        tarfile.open(altered, "w:gz") as destination,
    ):
        for member in source.getmembers():
            if not member.isfile():
                continue
            extracted = source.extractfile(member)
            assert extracted is not None
            content = extracted.read()
            relative = member.name.split("/", 1)[1]
            replacement = tarfile.TarInfo(f"other-0.1.0/{relative}")
            replacement.size = len(content)
            destination.addfile(replacement, io.BytesIO(content))

    with pytest.raises(
        DistributionError, match="sdist archive root does not match metadata"
    ):
        validate_sdist(altered)


def test_built_sdist_contains_all_contract_assets(tmp_path: Path) -> None:
    checkout = Path(__file__).resolve().parents[1]
    subprocess.run(
        ["uv", "build", "--sdist", "--out-dir", str(tmp_path)],
        cwd=checkout,
        check=True,
    )

    validate_sdist(next(tmp_path.glob("osqar_inspector-*.tar.gz")))


@pytest.mark.parametrize(
    ("member_name", "member_mode"),
    [
        ("../escape", stat.S_IFREG | 0o644),
        ("/absolute", stat.S_IFREG | 0o644),
        ("osqar_inspector//collision.py", stat.S_IFREG | 0o644),
        ("osqar_inspector\\backslash.py", stat.S_IFREG | 0o644),
        ("unexpected/file.txt", stat.S_IFREG | 0o644),
        ("osqar_inspector/link", stat.S_IFLNK | 0o777),
    ],
)
def test_wheel_rejects_unsafe_or_unexpected_members(
    tmp_path: Path, member_name: str, member_mode: int
) -> None:
    checkout = Path(__file__).resolve().parents[1]
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(wheelhouse)],
        cwd=checkout,
        check=True,
    )
    original = next(wheelhouse.glob("osqar_inspector-*.whl"))
    altered = tmp_path / original.name
    with (
        zipfile.ZipFile(original) as source,
        zipfile.ZipFile(altered, "w") as destination,
    ):
        for item in source.infolist():
            destination.writestr(item, source.read(item.filename))
        injected = zipfile.ZipInfo(member_name)
        injected.create_system = 3
        injected.external_attr = member_mode << 16
        destination.writestr(injected, b"target")

    with pytest.raises(DistributionError, match="unsafe or unexpected wheel member"):
        validate_wheel(altered)


@pytest.mark.parametrize(
    ("member_name", "member_type"),
    [
        ("../escape", tarfile.REGTYPE),
        ("/absolute", tarfile.REGTYPE),
        ("osqar_inspector-0.1.0//collision", tarfile.REGTYPE),
        ("osqar_inspector-0.1.0\\backslash", tarfile.REGTYPE),
        ("unexpected/file.txt", tarfile.REGTYPE),
        ("osqar_inspector-0.1.0/link", tarfile.SYMTYPE),
    ],
)
def test_sdist_rejects_unsafe_or_unexpected_members(
    tmp_path: Path, member_name: str, member_type: bytes
) -> None:
    checkout = Path(__file__).resolve().parents[1]
    dist = tmp_path / "dist"
    dist.mkdir()
    subprocess.run(
        ["uv", "build", "--sdist", "--out-dir", str(dist)],
        cwd=checkout,
        check=True,
    )
    original = next(dist.glob("osqar_inspector-*.tar.gz"))
    altered = tmp_path / original.name
    with (
        tarfile.open(original, "r:gz") as source,
        tarfile.open(altered, "w:gz") as destination,
    ):
        for member in source.getmembers():
            extracted = source.extractfile(member) if member.isfile() else None
            destination.addfile(member, extracted)
        injected = tarfile.TarInfo(member_name)
        injected.type = member_type
        if member_type == tarfile.SYMTYPE:
            injected.linkname = "target"
            destination.addfile(injected)
        else:
            injected.size = 1
            destination.addfile(injected, io.BytesIO(b"x"))

    with pytest.raises(DistributionError, match="unsafe or unexpected sdist member"):
        validate_sdist(altered)


def test_wheel_rejects_normalization_colliding_members(tmp_path: Path) -> None:
    checkout = Path(__file__).resolve().parents[1]
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(wheelhouse)],
        cwd=checkout,
        check=True,
    )
    original = next(wheelhouse.glob("osqar_inspector-*.whl"))
    altered = tmp_path / original.name
    with (
        zipfile.ZipFile(original) as source,
        zipfile.ZipFile(altered, "w") as destination,
    ):
        for item in source.infolist():
            destination.writestr(item, source.read(item.filename))
        destination.writestr("osqar_inspector/Case.py", b"")
        destination.writestr("osqar_inspector/case.py", b"")

    with pytest.raises(DistributionError, match="unsafe or unexpected wheel member"):
        validate_wheel(altered)


def test_wheel_rejects_unrecorded_package_member(tmp_path: Path) -> None:
    checkout = Path(__file__).resolve().parents[1]
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(wheelhouse)],
        cwd=checkout,
        check=True,
    )
    original = next(wheelhouse.glob("osqar_inspector-*.whl"))
    altered = tmp_path / original.name
    with (
        zipfile.ZipFile(original) as source,
        zipfile.ZipFile(altered, "w") as destination,
    ):
        for item in source.infolist():
            destination.writestr(item, source.read(item.filename))
        destination.writestr("osqar_inspector/unrecorded.py", b"")

    with pytest.raises(DistributionError, match="wheel RECORD does not match archive"):
        validate_wheel(altered)


def test_sdist_rejects_normalization_colliding_members(tmp_path: Path) -> None:
    checkout = Path(__file__).resolve().parents[1]
    dist = tmp_path / "dist"
    dist.mkdir()
    subprocess.run(
        ["uv", "build", "--sdist", "--out-dir", str(dist)],
        cwd=checkout,
        check=True,
    )
    original = next(dist.glob("osqar_inspector-*.tar.gz"))
    altered = tmp_path / original.name
    with (
        tarfile.open(original, "r:gz") as source,
        tarfile.open(altered, "w:gz") as destination,
    ):
        for member in source.getmembers():
            extracted = source.extractfile(member) if member.isfile() else None
            destination.addfile(member, extracted)
        for name in ("Case.py", "case.py"):
            injected = tarfile.TarInfo(f"osqar_inspector-0.1.0/{name}")
            destination.addfile(injected, io.BytesIO())

    with pytest.raises(DistributionError, match="unsafe or unexpected sdist member"):
        validate_sdist(altered)

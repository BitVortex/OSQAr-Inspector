from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

import pytest

from osqar_inspector import verify
from osqar_inspector.verify import VerificationError


FIXTURES = Path(__file__).parent / "fixtures"


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def valid_run_report() -> dict[str, Any]:
    digest = "0" * 64
    return {
        "artifact_counts": [{"count": "1", "kind": "api-page"}],
        "claim_boundary": {
            "does_not_establish": [
                "certification",
                "evidence-adequacy",
                "evidence-approval",
                "fitness-for-use",
                "functional-safety",
                "security",
                "software-qualification",
                "standards-compliance",
                "tool-qualification",
            ],
            "scope": "mechanical-structural-and-integrity-inspection",
        },
        "configuration_identity": {
            "controlled_input": {
                "path": "inspector.json",
                "sha256": digest,
                "size": "1",
            },
            "defaults": {"id": "builtin-v1", "sha256": digest},
            "overrides": [],
            "resolved": {"sha256": digest},
            "schema": {"id": "osqar.inspector.config.v1", "sha256": digest},
        },
        "diagnostics": [],
        "inspector": {"version": "0.1.0"},
        "optional_stages": {"degraded": [], "skipped": []},
        "plan_sha256": digest,
        "required_stage_decision": "satisfied",
        "schema": "osqar.inspector.run.v1",
        "snapshot_id": f"snapshot:sha256:{digest}",
        "stage_result_digests": [digest],
    }


def make_bundle(root: Path) -> str:
    payloads = {
        "index.html": b"<h1>Inspection</h1>\n",
        "reports/run.json": canonical(valid_run_report()),
    }
    for name, content in payloads.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return seal_bundle(root, payloads)


def seal_bundle(root: Path, payloads: dict[str, bytes]) -> str:
    manifest = canonical(
        {
            "entries": [
                {
                    "path": name,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size": str(len(content)),
                }
                for name, content in sorted(payloads.items())
            ],
            "entry_points": {
                "index": "index.html",
                "run_report": "reports/run.json",
            },
            "schema": "osqar.inspector.bundle-manifest.v1",
        }
    )
    (root / "manifest.json").write_bytes(manifest)
    checksums = b"".join(
        f"{hashlib.sha256(content).hexdigest()}  {name}\n".encode()
        for name, content in sorted({**payloads, "manifest.json": manifest}.items())
    )
    (root / "checksums.sha256").write_bytes(checksums)
    identity = canonical(
        {
            "identity": {
                "checksums_sha256": hashlib.sha256(checksums).hexdigest(),
                "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
            },
            "kind": "bundle",
        }
    )
    return f"bundle:sha256:{hashlib.sha256(identity).hexdigest()}"


def replace_payload(bundle: Path, path: str, content: bytes) -> None:
    payloads = {
        entry["path"]: (bundle / entry["path"]).read_bytes()
        for entry in json.loads((bundle / "manifest.json").read_bytes())["entries"]
    }
    payloads[path] = content
    target = bundle / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    seal_bundle(bundle, payloads)


def run_verify(bundle: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "osqar_inspector.cli", "verify", "--bundle", str(bundle)],
        text=True,
        capture_output=True,
        check=False,
    )


def test_valid_bundle(tmp_path: Path) -> None:
    bundle_id = make_bundle(tmp_path)
    result = run_verify(tmp_path)
    assert result.returncode == 0
    assert result.stderr == ""
    assert json.loads(result.stdout) == {"bundle_id": bundle_id, "valid": True}


def test_internal_link_missing_target_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    replace_payload(tmp_path, "index.html", b'<a href="missing.html">missing</a>')

    assert_failure(tmp_path, "link.missing_target")


def test_valid_relative_internal_link_passes(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    replace_payload(tmp_path, "guide/start.html", b'<a href="../target.html">target</a>')
    replace_payload(tmp_path, "target.html", b"<p>target</p>")

    result = run_verify(tmp_path)

    assert result.returncode == 0
    assert result.stderr == ""


def test_valid_root_relative_internal_link_passes(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    replace_payload(tmp_path, "guide/start.html", b'<a href="/target.html">target</a>')
    replace_payload(tmp_path, "target.html", b"<p>target</p>")

    result = run_verify(tmp_path)

    assert result.returncode == 0
    assert result.stderr == ""


def test_valid_directory_internal_link_resolves_to_index(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    replace_payload(tmp_path, "index.html", b'<a href="guide/">guide</a>')
    replace_payload(tmp_path, "guide/index.html", b"<p>guide</p>")

    result = run_verify(tmp_path)

    assert result.returncode == 0
    assert result.stderr == ""


def test_external_link_is_not_resolved_or_fetched(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    replace_payload(
        tmp_path,
        "index.html",
        b'<a href="https://unresolvable.invalid/missing">external</a>',
    )

    result = run_verify(tmp_path)

    assert result.returncode == 0
    assert result.stderr == ""


def test_malformed_external_reference_fails_typed(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    replace_payload(tmp_path, "index.html", b'<a href="http://[">malformed</a>')

    assert_failure(tmp_path, "link.invalid_reference")


def test_malformed_percent_escape_in_link_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    replace_payload(tmp_path, "index.html", b'<a href="bad%ZZ.html">bad</a>')

    assert_failure(tmp_path, "link.malformed_percent")


def test_percent_escape_that_is_invalid_utf8_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    replace_payload(tmp_path, "index.html", b'<a href="bad%FF.html">bad</a>')

    assert_failure(tmp_path, "link.invalid_percent_utf8")


def test_query_percent_escape_that_is_invalid_utf8_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    replace_payload(tmp_path, "index.html", b'<a href="target.html?q=%FF">bad</a>')
    replace_payload(tmp_path, "target.html", b"<p>target</p>")

    assert_failure(tmp_path, "link.invalid_percent_utf8")


def test_internal_link_cannot_escape_bundle_root(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    replace_payload(tmp_path, "index.html", b'<a href="../outside.html">outside</a>')

    assert_failure(tmp_path, "link.root_escape")


def test_html_payload_must_be_utf8(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    replace_payload(tmp_path, "index.html", b"<p>\xff</p>")

    assert_failure(tmp_path, "link.invalid_html_utf8")


def test_missing_html_fragment_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    replace_payload(tmp_path, "index.html", b'<a href="#missing">missing</a>')

    assert_failure(tmp_path, "link.missing_fragment")


def test_valid_percent_encoded_html_fragment_passes(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    replace_payload(
        tmp_path,
        "index.html",
        '<h2 id="café">section</h2><a href="#caf%C3%A9">section</a>'.encode(),
    )

    result = run_verify(tmp_path)

    assert result.returncode == 0
    assert result.stderr == ""


def test_valid_legacy_anchor_name_fragment_passes(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    replace_payload(
        tmp_path,
        "index.html",
        b'<a name="legacy"></a><a href="#legacy">legacy</a>',
    )

    result = run_verify(tmp_path)

    assert result.returncode == 0
    assert result.stderr == ""


def test_fragment_on_non_html_target_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    replace_payload(tmp_path, "index.html", b'<a href="asset.txt#part">asset</a>')
    replace_payload(tmp_path, "asset.txt", b"part")

    assert_failure(tmp_path, "link.non_html_fragment")


def test_duplicate_anchor_identity_is_ambiguous(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    replace_payload(
        tmp_path,
        "index.html",
        b'<h2 id="same">one</h2><a name="same"></a><a href="#same">same</a>',
    )

    assert_failure(tmp_path, "link.ambiguous_fragment")


def test_base_href_is_unsupported(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    replace_payload(tmp_path, "index.html", b'<base href="guide/">')

    assert_failure(tmp_path, "link.unsupported_base")


def test_srcset_is_unsupported(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    replace_payload(tmp_path, "index.html", b'<img srcset="small.png 1x">')

    assert_failure(tmp_path, "link.unsupported_srcset")


def test_src_attribute_missing_target_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    replace_payload(tmp_path, "index.html", b'<img src="missing.png">')

    assert_failure(tmp_path, "link.missing_target")


def test_object_data_missing_target_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    replace_payload(tmp_path, "index.html", b'<object data="missing.bin"></object>')

    assert_failure(tmp_path, "link.missing_target")


def test_video_poster_missing_target_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    replace_payload(tmp_path, "index.html", b'<video poster="missing.jpg"></video>')

    assert_failure(tmp_path, "link.missing_target")


def test_run_report_requires_supported_schema(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    report = valid_run_report()
    report["schema"] = "osqar.inspector.run.v2"
    replace_payload(tmp_path, "reports/run.json", canonical(report))

    assert_failure(tmp_path, "run_report.unsupported_schema")


def test_run_report_top_level_shape_is_closed(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    report = valid_run_report()
    report["unexpected"] = None
    replace_payload(tmp_path, "reports/run.json", canonical(report))

    assert_failure(tmp_path, "run_report.invalid_shape")


def test_run_report_bytes_must_be_canonical(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    content = json.dumps(valid_run_report(), indent=2).encode()
    replace_payload(tmp_path, "reports/run.json", content)

    assert_failure(tmp_path, "run_report.noncanonical")


def test_run_report_uses_rfc8785_utf16_property_order(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    report = valid_run_report()
    report["configuration_identity"]["overrides"] = [
        {"pointer": "/unicode", "value": {"\ue000": 1, "😀": 2}}
    ]
    content = canonical(report)
    python_order = '"value":{"\ue000":1,"😀":2}'.encode()
    rfc8785_order = '"value":{"😀":2,"\ue000":1}'.encode()
    assert python_order in content
    replace_payload(tmp_path, "reports/run.json", content.replace(python_order, rfc8785_order))

    result = run_verify(tmp_path)

    assert result.returncode == 0
    assert result.stderr == ""


def test_run_report_lone_surrogate_has_report_diagnostic(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    report = valid_run_report()
    report["configuration_identity"]["overrides"] = [
        {"pointer": "/unicode", "value": "placeholder"}
    ]
    content = canonical(report).replace(b'"value":"placeholder"', b'"value":"\\ud800"')
    replace_payload(tmp_path, "reports/run.json", content)

    assert_failure(tmp_path, "run_report.invalid_json")


def test_run_report_duplicate_member_has_typed_diagnostic(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    content = canonical(valid_run_report())
    content = content[:-1] + b',"schema":"osqar.inspector.run.v1"}'
    replace_payload(tmp_path, "reports/run.json", content)

    assert_failure(tmp_path, "run_report.duplicate_member")


def test_run_report_unhashable_diagnostic_severity_fails_typed(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    report = valid_run_report()
    report["diagnostics"] = [
        {"code": "stage.warning", "message": "warning", "path": None, "severity": []}
    ]
    replace_payload(tmp_path, "reports/run.json", canonical(report))

    assert_failure(tmp_path, "run_report.invalid_shape")


def test_run_report_unhashable_required_decision_fails_typed(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    report = valid_run_report()
    report["required_stage_decision"] = []
    replace_payload(tmp_path, "reports/run.json", canonical(report))

    assert_failure(tmp_path, "run_report.invalid_shape")


@pytest.mark.parametrize(
    "case",
    [
        "claim",
        "configuration-shape",
        "configuration-scalar",
        "pointer-escape",
        "pointer-order",
        "pointer-overlap",
        "unsafe-override-integer",
        "artifact-order",
        "stage-lists",
        "diagnostic",
        "digest-and-id",
        "decision-and-version",
    ],
)
def test_run_report_rejects_material_schema_violations(
    tmp_path: Path, case: str
) -> None:
    make_bundle(tmp_path)
    report = valid_run_report()
    digest = "0" * 64
    if case == "claim":
        report["claim_boundary"]["scope"] = "broader"
    elif case == "configuration-shape":
        report["configuration_identity"]["defaults"]["extra"] = True
    elif case == "configuration-scalar":
        report["configuration_identity"]["controlled_input"]["size"] = "01"
    elif case == "pointer-escape":
        report["configuration_identity"]["overrides"] = [
            {"pointer": "/bad~2escape", "value": None}
        ]
    elif case == "pointer-order":
        report["configuration_identity"]["overrides"] = [
            {"pointer": "/z", "value": None},
            {"pointer": "/a", "value": None},
        ]
    elif case == "pointer-overlap":
        report["configuration_identity"]["overrides"] = [
            {"pointer": "/a", "value": None},
            {"pointer": "/a/b", "value": None},
        ]
    elif case == "unsafe-override-integer":
        report["configuration_identity"]["overrides"] = [
            {"pointer": "/a", "value": 9007199254740992}
        ]
    elif case == "artifact-order":
        report["artifact_counts"] = [
            {"count": "1", "kind": "z-kind"},
            {"count": "0", "kind": "bad_kind"},
        ]
    elif case == "stage-lists":
        report["optional_stages"] = {
            "degraded": ["same", "same"],
            "skipped": ["same"],
        }
    elif case == "diagnostic":
        report["diagnostics"] = [
            {"code": "Bad Code", "message": "\n", "path": "../x", "severity": "fatal"}
        ]
    elif case == "digest-and-id":
        report["plan_sha256"] = "A" * 64
        report["stage_result_digests"] = [digest, digest]
        report["snapshot_id"] = f"run:sha256:{digest}"
    elif case == "decision-and-version":
        report["required_stage_decision"] = "unknown"
        report["inspector"]["version"] = "not valid!"
    replace_payload(tmp_path, "reports/run.json", canonical(report))

    assert_failure(tmp_path, "run_report.invalid_shape")


def test_altered_payload_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    (tmp_path / "index.html").write_bytes(b"altered")
    result = run_verify(tmp_path)
    assert result.returncode != 0
    assert result.stdout == ""
    assert json.loads(result.stderr)["diagnostics"][0]["code"] == "payload.size_mismatch"


def assert_failure(bundle: Path, code: str) -> None:
    result = run_verify(bundle)
    assert result.returncode != 0
    assert result.stdout == ""
    output = json.loads(result.stderr)
    assert output["valid"] is False
    assert output["diagnostics"][0]["code"] == code


def test_extra_file_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    (tmp_path / "extra.txt").write_text("extra")
    assert_failure(tmp_path, "inventory.extra_file")


def test_missing_payload_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    (tmp_path / "index.html").unlink()
    assert_failure(tmp_path, "inventory.missing_file")


def test_malformed_manifest_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    (tmp_path / "manifest.json").write_bytes(b"{")
    assert_failure(tmp_path, "manifest.invalid_json")


def test_oversized_integer_manifest_fails_with_typed_cli_json(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    (tmp_path / "manifest.json").write_bytes(b"9" * 5000)

    result = run_verify(tmp_path)

    assert result.returncode != 0
    assert result.stdout == ""
    assert "Traceback" not in result.stderr
    assert json.loads(result.stderr)["diagnostics"][0]["code"] == "manifest.invalid_json"


def test_canonical_recursion_error_is_invalid_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_bundle(tmp_path)

    def fail_dumps(*args: object, **kwargs: object) -> str:
        raise RecursionError("deterministic recursion failure")

    monkeypatch.setattr(verify.json, "dumps", fail_dumps)

    with pytest.raises(VerificationError) as caught:
        verify.verify_bundle(tmp_path)

    assert caught.value.diagnostic()["code"] == "manifest.invalid_json"


def test_huge_manifest_size_fails_with_typed_cli_json(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    rewrite_manifest(
        tmp_path,
        lambda value: value["entries"][0].update({"size": "9" * 5000}),
    )

    result = run_verify(tmp_path)

    assert result.returncode != 0
    assert result.stdout == ""
    assert "Traceback" not in result.stderr
    assert json.loads(result.stderr)["diagnostics"][0]["code"] == "payload.size_mismatch"


def test_deep_manifest_json_fails_with_typed_cli_json(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    (tmp_path / "manifest.json").write_bytes(b"[" * 10_000 + b"]" * 10_000)

    result = run_verify(tmp_path)

    assert result.returncode != 0
    assert result.stdout == ""
    assert "Traceback" not in result.stderr
    assert json.loads(result.stderr)["diagnostics"][0]["code"] == "manifest.invalid_json"


def test_unreadable_directory_entry_stat_has_typed_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class UnreadableEntry:
        name = "blocked.txt"
        path = str(tmp_path / name)

        def stat(self, *, follow_symlinks: bool) -> object:
            assert follow_symlinks is False
            raise OSError("deterministic stat failure")

    monkeypatch.setattr(verify.os, "scandir", lambda directory: [UnreadableEntry()])

    with pytest.raises(VerificationError) as caught:
        verify._inventory(tmp_path)

    assert caught.value.diagnostic() == {
        "code": "inventory.unreadable_entry",
        "message": "bundle directory entry cannot be inspected",
        "path": "blocked.txt",
    }


def test_checksum_mismatch_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    checksum_path = tmp_path / "checksums.sha256"
    checksum_path.write_bytes(b"0" + checksum_path.read_bytes()[1:])
    assert_failure(tmp_path, "checksums.noncanonical")


def test_path_escape_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["entries"][0]["path"] = "../escape"
    manifest_path.write_bytes(canonical(manifest))
    assert_failure(tmp_path, "path.invalid")


def test_symlink_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    (tmp_path / "index.html").unlink()
    (tmp_path / "index.html").symlink_to("reports/run.json")
    assert_failure(tmp_path, "inventory.forbidden_object")


def test_empty_directory_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    (tmp_path / "empty").mkdir()
    assert_failure(tmp_path, "inventory.extra_directory")


def rewrite_manifest(bundle: Path, change: Callable[[dict[str, Any]], None]) -> None:
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    change(manifest)
    manifest_path.write_bytes(canonical(manifest))


def test_same_size_payload_hash_mismatch_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    payload = tmp_path / "index.html"
    payload.write_bytes(b"x" * len(payload.read_bytes()))
    assert_failure(tmp_path, "payload.hash_mismatch")


def test_semantic_payload_swap_after_hash_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_bundle(tmp_path)
    replace_payload(tmp_path, "index.html", b'<a href="missing.html">missing</a>')
    original = verify._read_regular
    swapped = False

    def swap_before_read(root: Path, relative: str) -> bytes:
        nonlocal swapped
        if relative == "index.html" and not swapped:
            swapped = True
            payload = root / relative
            payload.write_bytes(b"x" * len(payload.read_bytes()))
        return original(root, relative)

    monkeypatch.setattr(verify, "_read_regular", swap_before_read)

    with pytest.raises(VerificationError) as caught:
        verify.verify_bundle(tmp_path)

    assert swapped
    assert caught.value.code == "payload.hash_mismatch"
    assert caught.value.path == "index.html"


def test_payload_swap_after_semantic_validation_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_bundle(tmp_path)
    original = verify._validate_links

    def swap_after_validation(
        root: Path, paths: set[str], expectations: dict[str, tuple[str, str]]
    ) -> None:
        original(root, paths, expectations)
        payload = root / "index.html"
        payload.write_bytes(b"x" * len(payload.read_bytes()))

    monkeypatch.setattr(verify, "_validate_links", swap_after_validation)

    with pytest.raises(VerificationError) as caught:
        verify.verify_bundle(tmp_path)

    assert caught.value.code == "payload.hash_mismatch"
    assert caught.value.path == "index.html"


def test_payload_verification_only_byte_reads_identity_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_bundle(tmp_path)
    original = verify._read_regular
    reads: list[str] = []

    def track_read(root: Path, relative: str) -> bytes:
        reads.append(relative)
        return original(root, relative)

    monkeypatch.setattr(verify, "_read_regular", track_read)

    verify.verify_bundle(tmp_path)

    assert reads == [
        "manifest.json",
        "checksums.sha256",
        "reports/run.json",
        "index.html",
        "manifest.json",
        "checksums.sha256",
    ]


def test_payload_hashing_reads_in_bounded_chunks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_bundle(tmp_path)
    original_open = Path.open
    payload_read_sizes: list[int] = []

    class TrackedFile:
        def __init__(self, handle: object) -> None:
            self.handle = handle

        def __enter__(self) -> "TrackedFile":
            self.handle.__enter__()
            return self

        def __exit__(self, *args: object) -> object:
            return self.handle.__exit__(*args)

        def read(self, size: int = -1) -> bytes:
            payload_read_sizes.append(size)
            return self.handle.read(size)

    def track_open(path: Path, *args: object, **kwargs: object) -> object:
        handle = original_open(path, *args, **kwargs)
        if path.name == "index.html":
            return TrackedFile(handle)
        return handle

    monkeypatch.setattr(Path, "open", track_open)

    verify.verify_bundle(tmp_path)

    assert payload_read_sizes
    hashing_reads = [size for size in payload_read_sizes if size != -1]
    assert hashing_reads
    assert all(0 < size <= 1024 * 1024 for size in hashing_reads)


def test_duplicate_manifest_member_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    manifest = (tmp_path / "manifest.json").read_bytes()
    (tmp_path / "manifest.json").write_bytes(
        manifest[:-1] + b',"schema":"osqar.inspector.bundle-manifest.v1"}'
    )
    assert_failure(tmp_path, "manifest.duplicate_member")


def test_noncanonical_manifest_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    value = json.loads(manifest_path.read_bytes())
    manifest_path.write_text(json.dumps(value, indent=2))
    assert_failure(tmp_path, "manifest.noncanonical")


def test_unknown_manifest_member_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    rewrite_manifest(tmp_path, lambda value: value.update({"unknown": "value"}))
    assert_failure(tmp_path, "manifest.invalid_shape")


def test_unsorted_entries_fail(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    rewrite_manifest(tmp_path, lambda value: value["entries"].reverse())
    assert_failure(tmp_path, "manifest.unsorted_entries")


def test_duplicate_entries_fail(tmp_path: Path) -> None:
    make_bundle(tmp_path)

    def duplicate(value: dict[str, object]) -> None:
        entries = value["entries"]
        assert isinstance(entries, list)
        entries.insert(0, entries[0])

    rewrite_manifest(tmp_path, duplicate)
    assert_failure(tmp_path, "manifest.duplicate_entry")


def test_invalid_entry_point_fails(tmp_path: Path) -> None:
    make_bundle(tmp_path)
    rewrite_manifest(
        tmp_path,
        lambda value: value["entry_points"].update({"index": "missing.html"}),
    )
    assert_failure(tmp_path, "manifest.invalid_entry_points")


def test_static_unicode_interoperability_fixture() -> None:
    bundle = FIXTURES / "valid-unicode-bundle"
    assert (bundle / "manifest.json").read_bytes() == (
        '{"entries":[{"path":"café.txt","sha256":'
        '"387c83cfb58da0289f50ca652fc16feece69811db1399e8a205599c8422fc350",'
        '"size":"1254"},{"path":"index.html","sha256":'
        '"11eba706ac3521b05f03e7879c573bf80ad595e1410f5f69d4abb764b79058d1",'
        '"size":"30"}],"entry_points":{"index":"index.html","run_report":"café.txt"},'
        '"schema":"osqar.inspector.bundle-manifest.v1"}'
    ).encode("utf-8")
    assert (bundle / "checksums.sha256").read_bytes() == (
        "387c83cfb58da0289f50ca652fc16feece69811db1399e8a205599c8422fc350  café.txt\n"
        "11eba706ac3521b05f03e7879c573bf80ad595e1410f5f69d4abb764b79058d1  index.html\n"
        "7e3a42a1b649a499cdffce717978ce42da371f021d89c9ec8b2c3677f5b6e736  manifest.json\n"
    ).encode("utf-8")

    result = run_verify(bundle)

    assert result.returncode == 0
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "bundle_id": "bundle:sha256:092d8a3987c79a7e8a35e8a39578234d54930122581d97afcb3c639396abd981",
        "valid": True,
    }

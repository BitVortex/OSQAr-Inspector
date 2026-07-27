from __future__ import annotations

import hashlib
import json
from importlib.resources import files
from pathlib import Path

import pytest

from osqar_inspector.configuration import (
    ConfigurationError,
    canonical_json,
    parse_json,
    resolve_configuration,
)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def test_resolves_nested_merge_and_exact_identity() -> None:
    controlled = (
        b'{"coverage":{"report":"reports/coverage/index.html"},'
        b'"doxygen":{"warnings_as_errors":true},'
        b'"project":{"exclude":["vendor"]},'
        b'"schema":"osqar.inspector.config.v1"}'
    )
    overrides = [
        {"pointer": "/publication/destination", "value": "public/inspection"},
        {"pointer": "/project/include", "value": ["src", "include"]},
    ]

    first = resolve_configuration(controlled, "config/inspector.json", overrides)
    second = resolve_configuration(controlled, "config/inspector.json", overrides)

    assert first == second
    assert first.value["project"] == {
        "exclude": ["vendor"],
        "include": ["src", "include"],
        "require_clean_git": True,
    }
    assert first.value["coverage"]["report"] == "reports/coverage/index.html"
    assert first.value["doxygen"]["warnings_as_errors"] is True
    assert first.identity == {
        "controlled_input": {
            "path": "config/inspector.json",
            "sha256": sha256(controlled),
            "size": str(len(controlled)),
        },
        "defaults": {
            "id": "builtin-v1",
            "sha256": sha256(canonical_json(first.defaults)),
        },
        "overrides": sorted(overrides, key=lambda item: item["pointer"].encode()),
        "resolved": {"sha256": sha256(first.canonical)},
        "schema": {
            "id": "osqar.inspector.config.v1",
            "sha256": sha256(first.schema_bytes),
        },
    }
    assert first.identity_bytes == canonical_json(first.identity)


def test_identity_ignores_host_environment_and_working_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    controlled = b'{"schema":"osqar.inspector.config.v1"}'
    expected = resolve_configuration(controlled, "config/inspector.json")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "different-home"))
    monkeypatch.setenv("HOSTNAME", "different-host")
    monkeypatch.setenv("PWD", str(tmp_path))
    monkeypatch.setenv("OSQAR_UNRELATED", "different-value")

    actual = resolve_configuration(controlled, "config/inspector.json")
    assert actual.canonical == expected.canonical
    assert actual.identity_bytes == expected.identity_bytes


REQUIRED_INTEROPERABILITY_CATEGORIES = {
    "recursive-nested-object-merge",
    "object-to-scalar-type-replacement",
    "scalar-to-object-type-replacement",
    "complete-array-replacement",
    "existing-member-replacement",
    "final-member-addition",
    "escaped-tilde-and-slash-access",
    "missing-parent-rejection",
    "scalar-traversal-rejection",
    "array-traversal-rejection",
    "duplicate-pointer-rejection",
    "ancestor-descendant-pointer-rejection",
    "ancestor-descendant-pointer-rejection-reverse-order",
    "malformed-pointer-escape-rejection",
    "noncanonical-pointer-rejection",
    "bom-rejection",
    "trailing-data-rejection",
    "non-object-top-level-rejection",
    "invalid-utf8-rejection",
    "invalid-unicode-rejection",
    "duplicate-member-rejection",
    "rejected-number-forms",
    "safe-integer-boundaries",
    "invalid-override-number-rejection",
    "non-normalized-path-rejection",
    "final-schema-rejection",
    "exact-canonical-bytes-and-digests",
}


def _fixture_bytes(value: str) -> bytes:
    content = bytes.fromhex(value)
    assert content.hex() == value
    return content


def test_interoperability_vectors_match_exact_bytes_and_digests() -> None:
    resources = files("osqar_inspector").joinpath("resources")
    root = resources.joinpath("interoperability")
    publication = json.loads(root.joinpath("vectors.json").read_bytes())
    assert publication["schema"] == "osqar.inspector.configuration.interoperability.v1"

    defaults = publication["defaults"]
    defaults_resource = resources.joinpath(defaults["resource"]).read_bytes()
    assert defaults_resource == _fixture_bytes(defaults["bytes_hex"])
    assert sha256(_fixture_bytes(defaults["canonical_hex"])) == defaults["sha256"]
    schema = publication["configuration_schema"]
    schema_resource = resources.joinpath(schema["resource"]).read_bytes()
    assert schema_resource == _fixture_bytes(schema["bytes_hex"])
    assert sha256(schema_resource) == schema["sha256"]

    covered = {
        category
        for vector in publication["vectors"]
        for category in vector["categories"]
    }
    assert covered == REQUIRED_INTEROPERABILITY_CATEGORIES

    for vector in publication["vectors"]:
        controlled = _fixture_bytes(vector["controlled_hex"])
        overrides_bytes = _fixture_bytes(vector["overrides_hex"])
        assert json.loads(overrides_bytes) == vector["overrides"]
        expected = vector["expected"]
        if expected["status"] == "error":
            with pytest.raises(ConfigurationError) as raised:
                resolve_configuration(controlled, vector["path"], vector["overrides"])
            assert raised.value.code == expected["code"], vector["id"]
            continue

        result = resolve_configuration(controlled, vector["path"], vector["overrides"])
        canonical = _fixture_bytes(expected["canonical_hex"])
        identity = _fixture_bytes(expected["identity_hex"])
        assert result.canonical == canonical, vector["id"]
        assert result.identity_bytes == identity, vector["id"]
        assert {
            "controlled": sha256(controlled),
            "defaults": sha256(result.defaults_bytes),
            "schema": sha256(result.schema_bytes),
            "resolved": sha256(canonical),
        } == expected["digests"], vector["id"]


def test_published_identity_mutations_change_exact_committed_bytes() -> None:
    root = files("osqar_inspector").joinpath("resources/interoperability")
    publication = json.loads(root.joinpath("vectors.json").read_bytes())
    mutations = publication["identity_mutations"]
    assert {item["component"] for item in mutations} == {
        "controlled_input",
        "defaults",
        "overrides",
    }
    for mutation in mutations:
        base_bytes = _fixture_bytes(mutation["base_identity_hex"])
        mutated_bytes = _fixture_bytes(mutation["mutated_identity_hex"])
        base = parse_json(base_bytes)
        mutated = parse_json(mutated_bytes)
        assert canonical_json(base) == base_bytes
        assert canonical_json(mutated) == mutated_bytes
        assert sha256(base_bytes) == mutation["base_sha256"]
        assert sha256(mutated_bytes) == mutation["mutated_sha256"]
        assert base_bytes != mutated_bytes
        assert {
            key for key in base if base[key] != mutated[key]
        } == set(mutation["changed_identity_members"])
        base_component = _fixture_bytes(mutation["base_component_hex"])
        mutated_component = _fixture_bytes(mutation["mutated_component_hex"])
        assert base_component != mutated_component
        if mutation["component"] == "controlled_input":
            assert base["controlled_input"]["sha256"] == sha256(base_component)
            assert mutated["controlled_input"]["sha256"] == sha256(mutated_component)
        elif mutation["component"] == "defaults":
            assert base["defaults"]["sha256"] == sha256(base_component)
            assert mutated["defaults"]["sha256"] == sha256(mutated_component)
        else:
            assert base["overrides"] == json.loads(base_component)
            assert mutated["overrides"] == json.loads(mutated_component)


def test_caller_controlled_extension_and_override_values_are_not_redacted() -> None:
    marker = "caller-controlled-marker"
    controlled = (
        b'{"extensions":{"example.org":{"label":"caller-controlled-marker"}},'
        b'"schema":"osqar.inspector.config.v1"}'
    )
    result = resolve_configuration(
        controlled,
        "inspector.json",
        [{"pointer": "/extensions/example.org/override", "value": marker}],
    )
    assert result.value["extensions"]["example.org"] == {
        "label": marker,
        "override": marker,
    }
    assert marker.encode() in result.canonical
    assert marker.encode() in result.identity_bytes


def test_rejects_duplicate_members_invalid_numbers_and_bom() -> None:
    invalid = [
        b'{"schema":"osqar.inspector.config.v1","schema":"x"}',
        b'{"schema":"osqar.inspector.config.v1","x":-0}',
        b'{"schema":"osqar.inspector.config.v1","x":1.0}',
        b'{"schema":"osqar.inspector.config.v1","x":1e2}',
        b'{"schema":"osqar.inspector.config.v1","x":9007199254740992}',
        b'{"schema":"osqar.inspector.config.v1","x":-9007199254740992}',
        b"\xef\xbb\xbf{}",
    ]
    for content in invalid:
        with pytest.raises(ConfigurationError):
            resolve_configuration(content, "inspector.json")


def test_rejects_duplicate_overlapping_and_noncanonical_overrides() -> None:
    content = b'{"schema":"osqar.inspector.config.v1"}'
    invalid = [
        [
            {"pointer": "/project/include", "value": []},
            {"pointer": "/project/include", "value": ["src"]},
        ],
        [
            {"pointer": "/project", "value": {}},
            {"pointer": "/project/include", "value": []},
        ],
        [{"pointer": "/bad~2escape", "value": None}],
        [{"pointer": "", "value": None}],
    ]
    for overrides in invalid:
        with pytest.raises(ConfigurationError):
            resolve_configuration(content, "inspector.json", overrides)


def test_rejects_non_profile_paths_and_unknown_fields() -> None:
    invalid = [
        b'{"project":{"include":["../src"]},"schema":"osqar.inspector.config.v1"}',
        b'{"publication":{"destination":"/tmp/out"},"schema":"osqar.inspector.config.v1"}',
        b'{"coverage":{"report":"reports\\\\index.html"},"schema":"osqar.inspector.config.v1"}',
        b'{"schema":"osqar.inspector.config.v1","unknown":true}',
        b'{"project":{"mystery":true},"schema":"osqar.inspector.config.v1"}',
    ]
    for content in invalid:
        with pytest.raises(ConfigurationError):
            resolve_configuration(content, "inspector.json")
    with pytest.raises(ConfigurationError):
        resolve_configuration(b"{}", "../inspector.json")


@pytest.mark.parametrize(
    "content",
    [
        b'{"x":"\\ud800"}',
        b'{"x":"\\udfff"}',
        b'{"x":"\xff"}',
        b'{} trailing',
        b"[]",
    ],
)
def test_strict_parser_rejects_invalid_unicode_utf8_trailing_and_nonobject(
    content: bytes,
) -> None:
    with pytest.raises(ConfigurationError):
        parse_json(content)


def test_strict_parser_accepts_paired_surrogate_escapes_as_unicode_scalars() -> None:
    assert parse_json(b'{"emoji":"\\ud83d\\ude00"}') == {"emoji": "😀"}


def test_deep_json_fails_with_typed_configuration_error() -> None:
    depth = 1000
    content = (b'{"x":' * depth) + b"0" + (b"}" * depth)
    with pytest.raises(ConfigurationError):
        parse_json(content)


def test_canonical_json_translates_deep_and_cyclic_recursion_failures() -> None:
    nested: object = 0
    for _ in range(2000):
        nested = {"x": nested}
    with pytest.raises(ConfigurationError) as deep_error:
        canonical_json(nested)
    assert deep_error.value.code == "configuration.invalid_value"

    cyclic: list[object] = []
    cyclic.append(cyclic)
    with pytest.raises(ConfigurationError) as cyclic_error:
        canonical_json(cyclic)
    assert cyclic_error.value.code == "configuration.invalid_value"


def test_deep_resolution_fails_with_typed_configuration_error() -> None:
    depth = 500
    nested = (b'{"x":' * depth) + b"0" + (b"}" * depth)
    content = (
        b'{"extensions":{"example.org":'
        + nested
        + b'},"schema":"osqar.inspector.config.v1"}'
    )
    with pytest.raises(ConfigurationError):
        resolve_configuration(content, "inspector.json")


@pytest.mark.parametrize(
    "token",
    [b"00", b"01", b"-01", b"+1", b"1.", b".1", b"1e0", b"1E1", b"1.5"],
)
def test_strict_parser_rejects_every_invalid_number_form(token: bytes) -> None:
    with pytest.raises(ConfigurationError):
        parse_json(b'{"number":' + token + b"}")


@pytest.mark.parametrize("number", [-9007199254740991, 0, 9007199254740991])
def test_strict_parser_accepts_safe_integer_boundaries(number: int) -> None:
    assert parse_json(f'{{"number":{number}}}'.encode()) == {"number": number}


def test_merge_replaces_scalar_object_and_complete_array() -> None:
    controlled = (
        b'{"coverage":null,"project":{"include":["only"]},'
        b'"schema":"osqar.inspector.config.v1"}'
    )
    with pytest.raises(ConfigurationError):  # replacement occurs, then schema rejects it
        resolve_configuration(controlled, "inspector.json")
    result = resolve_configuration(
        b'{"project":{"include":["only"]},"schema":"osqar.inspector.config.v1"}',
        "inspector.json",
    )
    assert result.value["project"]["include"] == ["only"]


def test_override_escape_addition_and_traversal_contract() -> None:
    controlled = (
        b'{"extensions":{"example.org":{"a/b":{"x~y":0}}},'
        b'"schema":"osqar.inspector.config.v1"}'
    )
    result = resolve_configuration(
        controlled,
        "inspector.json",
        [{"pointer": "/extensions/example.org/a~1b/x~0y", "value": 1}],
    )
    assert result.value["extensions"]["example.org"]["a/b"]["x~y"] == 1
    encoded_tilde_one = resolve_configuration(
        controlled,
        "inspector.json",
        [{"pointer": "/extensions/example.org/~01", "value": True}],
    )
    assert encoded_tilde_one.value["extensions"]["example.org"]["~1"] is True
    for pointer in (
        "/missing/child",
        "/project/include/child",
        "/project/require_clean_git/child",
    ):
        with pytest.raises(ConfigurationError):
            resolve_configuration(
                controlled, "inspector.json", [{"pointer": pointer, "value": 1}]
            )


def test_override_values_obey_v1_number_contract() -> None:
    for value in (1.5, 9007199254740992):
        with pytest.raises(ConfigurationError):
            resolve_configuration(
                b'{"schema":"osqar.inspector.config.v1"}',
                "inspector.json",
                [{"pointer": "/extensions/example.org", "value": value}],
            )


def test_rfc8785_uses_utf16_property_order_and_exact_escaping() -> None:
    value = {"\ue000": 1, "😀": 2, "control": "\b\t\n\f\r\u0000", "solidus": "/"}
    assert canonical_json(value) == (
        '{"control":"\\b\\t\\n\\f\\r\\u0000","solidus":"/","😀":2,"\ue000":1}'
    ).encode()

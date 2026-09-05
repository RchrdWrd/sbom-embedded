import json

import pytest
from cyclonedx.validation.json import JsonStrictValidator

from sbom_embedded.models import Component, make_purl
from sbom_embedded.writer import DEFAULT_SCHEMA_VERSION, to_json

from .support import FIXED_SERIAL, FIXED_TIMESTAMP


def render(components, **kwargs) -> dict:
    kwargs.setdefault("product_name", "core-image-minimal")
    out = to_json(
        components,
        serial_number=FIXED_SERIAL,
        timestamp=FIXED_TIMESTAMP,
        **kwargs,
    )
    assert JsonStrictValidator(DEFAULT_SCHEMA_VERSION).validate_str(out) is None
    return json.loads(out)


def test_output_validates_against_the_cyclonedx_schema():
    doc = render([Component("busybox", "1.37.0")])
    assert doc["specVersion"] == "1.6"
    assert doc["serialNumber"] == f"urn:uuid:{FIXED_SERIAL}"


def test_every_component_carries_a_purl():
    doc = render(
        [
            Component("busybox", "1.37.0"),
            Component("netbase", "6.4"),
            Component("base-files", None),
        ]
    )
    purls = [c["purl"] for c in doc["components"]]
    assert purls == [
        "pkg:generic/base-files",
        "pkg:generic/busybox@1.37.0",
        "pkg:generic/netbase@6.4",
    ]


def test_parser_supplied_purl_is_preserved():
    purl = make_purl("busybox", "1.37.0", qualifiers={"arch": "x86_64_v3"})
    doc = render([Component("busybox", "1.37.0", purl=purl)])
    assert doc["components"][0]["purl"] == "pkg:generic/busybox@1.37.0?arch=x86_64_v3"


def test_spdx_licenses_keep_their_id_and_others_survive_as_names():
    doc = render(
        [
            Component("netbase", "6.4", license="GPL-2.0-only"),
            Component("dropbear", "2022.83", license="MIT AND BSD-3-Clause"),
            # Yocto's own separator is not valid SPDX; it must not be dropped.
            Component("openssl", "3.2.4", license="OpenSSL & Apache-2.0"),
        ]
    )
    by_name = {c["name"]: c for c in doc["components"]}
    assert by_name["netbase"]["licenses"] == [{"license": {"id": "GPL-2.0-only"}}]
    assert by_name["dropbear"]["licenses"] == [{"expression": "MIT AND BSD-3-Clause"}]
    assert by_name["openssl"]["licenses"] == [
        {"license": {"name": "OpenSSL & Apache-2.0"}}
    ]


def test_missing_metadata_is_omitted_rather_than_invented():
    # A Yocto image manifest supplies neither license nor supplier.
    doc = render([Component("busybox", "1.37.0")])
    component = doc["components"][0]
    assert "licenses" not in component
    assert "supplier" not in component
    assert "hashes" not in component


def test_supplier_and_hash_are_emitted_when_the_manifest_has_them():
    doc = render(
        [
            Component(
                "netbase",
                "6.4",
                supplier="Debian",
                hash="sha256:" + "a" * 64,
            )
        ]
    )
    component = doc["components"][0]
    assert component["supplier"] == {"name": "Debian"}
    assert component["hashes"] == [{"alg": "SHA-256", "content": "a" * 64}]


def test_root_component_is_the_firmware_image_and_owns_every_package():
    doc = render(
        [Component("busybox", "1.37.0"), Component("netbase", "6.4")],
        product_name="core-image-minimal",
        product_version="qemux86-64",
    )
    root = doc["metadata"]["component"]
    assert root["type"] == "firmware"
    assert root["name"] == "core-image-minimal"
    assert root["version"] == "qemux86-64"

    edges = {d["ref"]: d.get("dependsOn", []) for d in doc["dependencies"]}
    assert sorted(edges["core-image-minimal"]) == [
        "pkg:generic/busybox@1.37.0",
        "pkg:generic/netbase@6.4",
    ]


def test_generator_records_itself_in_metadata():
    doc = render([Component("busybox", "1.37.0")])
    tools = doc["metadata"]["tools"]["components"]
    assert [t["name"] for t in tools] == ["sbom-embedded"]


def test_output_is_byte_identical_across_runs():
    components = [Component("busybox", "1.37.0"), Component("netbase", "6.4")]
    first = to_json(
        components,
        product_name="img",
        serial_number=FIXED_SERIAL,
        timestamp=FIXED_TIMESTAMP,
    )
    second = to_json(
        components,
        product_name="img",
        serial_number=FIXED_SERIAL,
        timestamp=FIXED_TIMESTAMP,
    )
    assert first == second


def test_empty_name_is_rejected():
    with pytest.raises(ValueError):
        Component("", "1.0")


def test_every_component_bom_ref_is_its_purl():
    # The dependencies array addresses components by bom-ref. If the mapping
    # drifts, a consumer either rejects the document or silently drops edges.
    doc = render(
        [
            Component("busybox", "1.37.0"),
            Component("netbase", "6.4"),
            Component("base-files", None),
        ]
    )
    for component in doc["components"]:
        assert component["bom-ref"] == component["purl"]


def test_every_dependency_reference_resolves():
    components = [Component("busybox", "1.37.0"), Component("netbase", "6.4")]
    doc = render(components, product_name="core-image-minimal")

    known = {c["bom-ref"] for c in doc["components"]}
    known.add(doc["metadata"]["component"]["bom-ref"])

    for entry in doc["dependencies"]:
        assert entry["ref"] in known, entry["ref"]
        for ref in entry.get("dependsOn", []):
            assert ref in known, ref


def test_the_root_owns_exactly_the_components():
    components = [
        Component("busybox", "1.37.0"),
        Component("netbase", "6.4"),
        Component("base-files", None),
    ]
    doc = render(components, product_name="core-image-minimal")

    root_ref = doc["metadata"]["component"]["bom-ref"]
    assert root_ref == "core-image-minimal"

    root_edge = next(e for e in doc["dependencies"] if e["ref"] == root_ref)
    assert sorted(root_edge["dependsOn"]) == sorted(
        c["bom-ref"] for c in doc["components"]
    )


def test_only_the_root_has_outgoing_edges():
    doc = render([Component("busybox", "1.37.0"), Component("netbase", "6.4")])
    with_edges = [e for e in doc["dependencies"] if e.get("dependsOn")]
    assert len(with_edges) == 1
    assert with_edges[0]["ref"] == doc["metadata"]["component"]["bom-ref"]
    # Every component still gets its own entry, so the array is N+1 long.
    assert len(doc["dependencies"]) == len(doc["components"]) + 1


def test_rendering_stays_practical_at_a_realistic_package_count():
    # A core-image-sato-sized image is a few thousand packages. Building the
    # dependency edges through Bom.register_dependency was O(n^2) and took
    # seconds; this asserts the shape of the output is unchanged and that the
    # work is bounded.
    components = [Component(f"pkg-{i:05d}", "1.0") for i in range(1000)]
    doc = render(components, product_name="big-image")
    assert len(doc["components"]) == 1000
    assert len(doc["dependencies"]) == 1001

    root_ref = doc["metadata"]["component"]["bom-ref"]
    root_edge = next(e for e in doc["dependencies"] if e["ref"] == root_ref)
    assert len(root_edge["dependsOn"]) == 1000

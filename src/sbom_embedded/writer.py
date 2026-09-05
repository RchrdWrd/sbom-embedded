"""CycloneDX output.

Written once, against `Component`. Parsers never touch CycloneDX types, so
the schema details -- and the library that validates them -- live here alone.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import fields
from datetime import datetime
from uuid import UUID

from cyclonedx.contrib.hash.factories import HashTypeFactory
from cyclonedx.contrib.license.factories import LicenseFactory
from cyclonedx.model import Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component as CdxComponent
from cyclonedx.model.component import ComponentType
from cyclonedx.model.contact import OrganizationalEntity
from cyclonedx.model.dependency import Dependency
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion
from packageurl import PackageURL

from . import __version__
from .models import Component

# 1.6 is what the CRA-adjacent tooling (Dependency-Track, Grype, Trivy) reads
# today; 1.7 is newer than most of it.
DEFAULT_SCHEMA_VERSION = SchemaVersion.V1_6

_licenses = LicenseFactory()
_hashes = HashTypeFactory()


class DuplicateBomRefError(ValueError):
    """Two components would claim one bom-ref, which CycloneDX forbids."""


def _bom_ref(component: Component) -> str:
    """The bom-ref this component will carry once rendered.

    Deliberately the same derivation `_to_cyclonedx` uses, rather than the raw
    `Component.purl`. Keying the duplicate check on one string and emitting
    another is how a collision slips through: `PackageURL.from_string`
    re-normalises path segments, so two purls that differ as strings can render
    as one ref -- and the library would then invent a random `BomRef.<n>` for
    the loser, which is exactly what this check exists to prevent.
    """
    if not component.purl:
        return component.name
    try:
        return PackageURL.from_string(component.purl).to_string()
    except ValueError:
        # An unparseable purl cannot round-trip; compare it as given rather
        # than silently treating it as equal to everything else that fails.
        return component.purl


def resolve_duplicates(
    components: Iterable[Component],
) -> tuple[list[Component], list[str]]:
    """Collapse components that merely repeat; refuse ones that contradict.

    CycloneDX 1.6 requires every bom-ref to be unique within a document, and
    this tool sets bom-ref to the purl. The JSON schema does not enforce that
    rule -- it lives in prose in the schema's own description -- and
    cyclonedx-python-lib resolves a collision by inventing a `BomRef.<n>` for
    the loser: a value that changes on every run, and that gets no entry in
    `dependencies` at all. A duplicate therefore costs both reproducible output
    and a component's place in the graph, and validation never notices.

    No manifest a build system writes can contain one. Bitbake builds both the
    image manifest and the license manifest from a dict keyed on package name,
    and Buildroot's `legal-manifest` appends exactly one row per package per
    invocation. Duplicates come from outside a clean build: a stale
    `legal-info/` that a second `make <pkg>-legal-info` appended to, manifests
    concatenated by hand to work around the several-images refusal, or an
    edited file.

    So the two cases are genuinely different. Where the repeated records agree,
    the package has been named twice and one entry is simply the truth --
    emitting it twice would assert that the image contains two copies. Where
    they disagree, nothing here can say which is right, and picking one would
    put invented data into a compliance document.

    Returns the components to render, and a note per collapsed purl for the
    caller to report; collapsing without a word would be its own silent edit.
    """
    kept: list[Component] = []
    seen: dict[str, Component] = {}
    repeats: dict[str, int] = {}

    for component in components:
        ref = _bom_ref(component)
        previous = seen.get(ref)
        if previous is None:
            seen[ref] = component
            kept.append(component)
            continue
        if previous == component:
            repeats[ref] = repeats.get(ref, 0) + 1
            continue
        differing = ", ".join(
            field.name
            for field in fields(Component)
            if getattr(previous, field.name) != getattr(component, field.name)
        )
        raise DuplicateBomRefError(
            f"two components share the purl {ref} but disagree on {differing}; "
            f"no single build writes a manifest like this -- check for a stale "
            f"legal-info directory, or manifests concatenated from two builds"
        )

    notes = [
        f"{ref} appears {count + 1} times; kept one" for ref, count in repeats.items()
    ]
    return kept, notes


def _to_cyclonedx(component: Component) -> CdxComponent:
    """Translate one parsed component into a CycloneDX component."""
    licenses = []
    if component.license:
        # Yocto writes "GPL-2.0-only & MIT" and Buildroot "GPL-2.0+, MIT" --
        # neither is a valid SPDX expression. make_from_string keeps a real
        # SPDX id or expression as such and falls back to a named license
        # instead of dropping the string on the floor.
        licenses.append(_licenses.make_from_string(component.license))

    hashes = []
    if component.hash:
        hashes.append(_hashes.from_composite_str(component.hash))

    # PackageURL.from_string re-normalises each path segment, so parsing a purl
    # and re-emitting it is not always the identity -- a name containing both a
    # slash and whitespace comes back shorter. Taking bom-ref from the raw
    # string while the purl field comes from the parsed object would let the
    # document's two copies of one identity disagree.
    purl = PackageURL.from_string(component.purl) if component.purl else None

    return CdxComponent(
        name=component.name,
        version=component.version,
        type=ComponentType.LIBRARY,
        purl=purl,
        bom_ref=purl.to_string() if purl is not None else component.purl,
        supplier=(
            OrganizationalEntity(name=component.supplier)
            if component.supplier
            else None
        ),
        licenses=licenses or None,
        hashes=hashes or None,
        properties=[
            Property(name=name, value=value)
            for name, value in sorted(component.properties.items())
        ]
        or None,
    )


def build_bom(
    components: Iterable[Component],
    *,
    product_name: str,
    product_version: str | None = None,
    serial_number: UUID | None = None,
    timestamp: datetime | None = None,
) -> Bom:
    """Assemble a BOM whose root component is the image itself.

    `serial_number` and `timestamp` exist so tests (and reproducible builds)
    can pin the two fields that would otherwise change on every run.
    """
    resolved, _ = resolve_duplicates(components)

    # The root shares the bom-ref namespace with every component, and its ref is
    # the product name -- which --name puts entirely under the user's control.
    if any(product_name == _bom_ref(component) for component in resolved):
        raise DuplicateBomRefError(
            f"the product name {product_name!r} is also a component's purl, so "
            f"both would claim one bom-ref; pass a different --name"
        )

    bom = Bom(serial_number=serial_number)

    root = CdxComponent(
        name=product_name,
        version=product_version,
        # The deliverable is a firmware image, not an application -- this is
        # the distinction a CRA reviewer cares about.
        type=ComponentType.FIRMWARE,
        bom_ref=product_name,
    )
    bom.metadata.component = root
    if timestamp is not None:
        bom.metadata.timestamp = timestamp
    bom.metadata.tools.components.add(
        CdxComponent(
            name="sbom-embedded",
            version=__version__,
            type=ComponentType.APPLICATION,
        )
    )

    rendered = [_to_cyclonedx(component) for component in resolved]
    for cdx in rendered:
        bom.components.add(cdx)

    # Every package is a direct part of the image. This is not a real
    # dependency graph -- the manifests do not carry one -- but consumers that
    # walk `dependencies` from the root would otherwise see nothing.
    #
    # Built directly rather than through Bom.register_dependency, which does a
    # linear `next(filter(...))` over the whole dependency set on every call
    # and so costs O(n^2). Measured, for byte-identical output: at 2000
    # components this loop takes 1.8 s against 11.9 s through
    # register_dependency.
    #
    # It does not make the whole render linear, and the earlier claim here that
    # 4000 packages rendered in 1.6 s was wrong by more than an order of
    # magnitude. `output_as_string()` calls `Bom.validate()`, which calls
    # `register_dependency` once per component to guarantee exactly the entries
    # this loop has already created -- so the quadratic scan happens anyway,
    # inside the library, and dominates: 2000 components render in about 14 s
    # here, 4000 in about 54 s. There is no public way to skip it. See §12 of
    # DESIGN.md.
    bom.dependencies.add(
        Dependency(
            ref=root.bom_ref,
            dependencies=[Dependency(ref=cdx.bom_ref) for cdx in rendered],
        )
    )
    for cdx in rendered:
        bom.dependencies.add(Dependency(ref=cdx.bom_ref))

    return bom


def to_json(
    components: Iterable[Component],
    *,
    product_name: str,
    product_version: str | None = None,
    serial_number: UUID | None = None,
    timestamp: datetime | None = None,
    schema_version: SchemaVersion = DEFAULT_SCHEMA_VERSION,
) -> str:
    """Render components as a CycloneDX JSON document."""
    bom = build_bom(
        components,
        product_name=product_name,
        product_version=product_version,
        serial_number=serial_number,
        timestamp=timestamp,
    )
    outputter = make_outputter(bom, OutputFormat.JSON, schema_version)
    return outputter.output_as_string(indent=2)

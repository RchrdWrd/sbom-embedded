"""CycloneDX output.

Written once, against `Component`. Parsers never touch CycloneDX types, so
the schema details -- and the library that validates them -- live here alone.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from uuid import UUID

from cyclonedx.contrib.hash.factories import HashTypeFactory
from cyclonedx.contrib.license.factories import LicenseFactory
from cyclonedx.model import Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component as CdxComponent
from cyclonedx.model.component import ComponentType
from cyclonedx.model.contact import OrganizationalEntity
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

    return CdxComponent(
        name=component.name,
        version=component.version,
        type=ComponentType.LIBRARY,
        purl=PackageURL.from_string(component.purl) if component.purl else None,
        bom_ref=component.purl,
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

    for component in components:
        cdx = _to_cyclonedx(component)
        bom.components.add(cdx)
        # Every package is a direct part of the image. This is not a real
        # dependency graph -- the manifests do not carry one -- but consumers
        # that walk `dependencies` from the root would otherwise see nothing.
        bom.register_dependency(root, [cdx])

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

"""Buildroot build output.

Reads `output/legal-info/manifest.csv`, the CSV `make legal-info` writes. Only
the target manifest is read: `host-manifest.csv` lists build-time tools such
as ccache and pkgconf, which are not part of the shipped firmware.

Columns are looked up by header name rather than by position, because the
column set has changed over the years -- `DEPENDENCIES WITH LICENSES` was
added in 2018.11, so a manifest from 2017 has six columns and one from 2023
has seven. Only PACKAGE, VERSION and LICENSE are read, and all three are
required; anything else in the header is ignored, which is what lets both
shapes parse.
"""

from __future__ import annotations

import csv
from pathlib import Path

from ..models import Component, make_purl


class BuildrootParseError(Exception):
    """The directory does not hold a Buildroot legal-info manifest."""


MANIFEST_NAME = "manifest.csv"

# Header spellings seen across releases, newest first.
_PACKAGE = ("PACKAGE",)
_VERSION = ("VERSION",)
_LICENSE = ("LICENSE",)

# Buildroot writes these literals when it has nothing real to record. Carrying
# them through would put a package named "unknown" at version "custom" into an
# SBOM, which reads as data rather than as the absence of data.
_NO_LICENSE = {"", "unknown"}
_NO_VERSION = {"", "custom"}


def find_manifest(root: Path) -> Path:
    """Locate manifest.csv from whatever the user pointed us at.

    Accepts the legal-info directory, the output directory above it, or the
    file itself, because all three are things a person reasonably types.
    """
    if root.is_file():
        return root
    for candidate in (root / MANIFEST_NAME, root / "legal-info" / MANIFEST_NAME):
        if candidate.is_file():
            return candidate
    raise BuildrootParseError(f"no {MANIFEST_NAME} found in or under {root}")


def _column(header: list[str], names: tuple[str, ...], path: Path) -> int:
    for name in names:
        if name in header:
            return header.index(name)
    raise BuildrootParseError(f"{path}: no {names[0]} column in header {header!r}")


def parse_manifest_csv(path: Path) -> list[Component]:
    """Read a legal-info manifest into components."""
    # newline="" is required by the csv module and matters here: real
    # manifests in the wild carry CRLF endings. utf-8-sig drops a BOM if an
    # editor introduced one.
    try:
        with path.open(newline="", encoding="utf-8-sig") as handle:
            rows = list(csv.reader(handle))
    except (OSError, UnicodeDecodeError, csv.Error) as err:
        # A non-UTF-8 byte, an unreadable file, or a field over the csv
        # module's limit would otherwise escape as a traceback.
        raise BuildrootParseError(f"{path}: cannot read: {err}") from err

    if not rows:
        raise BuildrootParseError(f"{path}: file is empty")

    header = [cell.strip() for cell in rows[0]]
    package_at = _column(header, _PACKAGE, path)
    version_at = _column(header, _VERSION, path)
    license_at = _column(header, _LICENSE, path)

    components: list[Component] = []
    for lineno, row in enumerate(rows[1:], 2):
        if not any(cell.strip() for cell in row):
            continue
        # Only the three columns actually read have to be present. A row with
        # fewer trailing columns than the header is common in older manifests
        # and harmless; one too short to reach LICENSE is not.
        needed = max(package_at, version_at, license_at) + 1
        if len(row) < needed:
            raise BuildrootParseError(
                f"{path}:{lineno}: need at least {needed} columns to reach "
                f"PACKAGE, VERSION and LICENSE, got {len(row)}"
            )
        name = row[package_at].strip()
        if not name:
            raise BuildrootParseError(f"{path}:{lineno}: empty package name")

        raw_version = row[version_at].strip()
        version = None if raw_version in _NO_VERSION else raw_version

        raw_license = row[license_at].strip()
        license_ = None if raw_license in _NO_LICENSE else raw_license

        components.append(
            Component(
                name=name,
                version=version,
                license=license_,
                purl=make_purl(name, version),
            )
        )
    return components


def parse(root: Path) -> tuple[list[Component], str]:
    """Parse a Buildroot legal-info directory.

    Returns the components and a label for the SBOM's root component.
    Buildroot has no image name of its own, so the caller is expected to
    override the label when the product has a real name.
    """
    manifest = find_manifest(root)
    return parse_manifest_csv(manifest), "buildroot"

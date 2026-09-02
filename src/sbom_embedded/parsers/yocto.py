"""Yocto / OpenEmbedded build output.

Reads what a finished build already wrote to `tmp/deploy`. Nothing here runs
bitbake, and nothing here needs the build tree to still exist.

The image manifest is written by `format_pkg_list(..., "ver")` in
oe/utils.py as `"%s %s %s" % (pkg, arch, ver)` -- one space, no quoting, no
header. That has been stable across every release and every package backend.
What is *in* those columns is not, which is what the parsing below is about.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from ..models import Component, make_purl


class YoctoParseError(Exception):
    """The deploy directory does not hold what we need to read."""


# The rpm backend reports a bare PKGV; deb and ipk both report the control
# file's Version field, which is "[PKGE:]PKGV-PKGR" -- so the same image built
# with PACKAGE_CLASSES=package_ipk yields "1.36.1-r0" where rpm yields
# "1.36.1". PKGR is Yocto's packaging revision and PKGE its epoch; neither is
# part of the upstream version a CVE feed knows. Stripping them is what makes
# the SBOM identical regardless of which backend produced the image.
_EPOCH = re.compile(r"^(?P<epoch>\d+):(?P<rest>.*)$")
_REVISION = re.compile(r"-(?P<revision>r\d+)$")


def normalize_version(raw: str) -> str:
    """Reduce a package-manager version string to the upstream version.

    The `+git0+<sha>` suffix OE appends to git recipes is deliberately kept:
    it is part of PKGV and identifies the actual source revision.
    """
    version = raw
    if match := _EPOCH.match(version):
        version = match["rest"]
    if match := _REVISION.search(version):
        version = version[: match.start()]
    return version


class ManifestKind(StrEnum):
    """Which artifact a manifest file is, in order of usefulness.

    LICENSE wins wherever both describe the same image: it is a complete
    inventory of the installed packages *and* carries licenses and recipe
    names, which the image manifest does not.
    """

    LICENSE = "license"
    IMAGE = "image"


@dataclass(frozen=True)
class ManifestFile:
    """A manifest found in a deploy directory, and what it describes."""

    path: Path
    kind: ManifestKind
    # "core-image-minimal-qemux86-64" -- the SBOM's root component name.
    label: str
    # The image alone, when the machine could be split off the label. Image
    # manifests always can (the machine is their parent directory); license
    # manifests only can when an image manifest revealed the machine name.
    image: str | None = None

    def matches(self, selector: str) -> bool:
        return selector == self.label or selector == self.image

    @property
    def choice(self) -> str:
        return self.image or self.label


# Yocto appends a build timestamp to the license directory and writes a
# symlink without it: "<image>-<machine>.rootfs-20250610090225" beside
# "<image>-<machine>.rootfs". Releases before 4.3 omit the ".rootfs" infix.
_TIMESTAMPED = re.compile(r"-\d{14}$")


def _license_label(directory: Path) -> str:
    return _TIMESTAMPED.sub("", directory.name).removesuffix(".rootfs")


def find_license_manifests(deploy: Path, machines: set[str]) -> list[ManifestFile]:
    """Locate every `license.manifest` under a deploy directory.

    The arch level in `licenses/<arch>/<image>-<machine>/` was added in Yocto
    4.3, so both depths are searched. `image_license.manifest` is deliberately
    not picked up: it describes deployed artifacts, not installed packages.
    """
    found: dict[str, ManifestFile] = {}
    licenses = deploy / "licenses"
    for pattern in ("*/license.manifest", "*/*/license.manifest"):
        for path in sorted(licenses.glob(pattern)):
            label = _license_label(path.parent)
            if label in found:
                # The timestamped directory and its symlink hold the same file.
                continue
            image = next(
                (
                    label.removesuffix(f"-{m}")
                    for m in machines
                    if label.endswith(f"-{m}")
                ),
                None,
            )
            found[label] = ManifestFile(
                path=path, kind=ManifestKind.LICENSE, label=label, image=image
            )
    return list(found.values())


def find_image_manifests(deploy: Path) -> list[ManifestFile]:
    """Locate every image manifest under a `tmp/deploy` directory.

    Yocto writes a timestamped manifest plus a stable symlink to it. Only the
    stable name is returned, so an image is never counted twice. Releases
    before 4.3 omit the `.rootfs` infix, which is why it is stripped
    optionally rather than required.
    """
    found: list[ManifestFile] = []
    for path in sorted((deploy / "images").glob("*/*.manifest")):
        machine = path.parent.name
        # "core-image-minimal-qemux86-64.rootfs.manifest" -> "core-image-minimal"
        stem = path.name.removesuffix(".manifest").removesuffix(".rootfs")
        if not stem.endswith(f"-{machine}"):
            # A timestamped copy (or a -dbg/SDK manifest). The symlink beside
            # it carries the same content under the stable name.
            continue
        image = stem.removesuffix(f"-{machine}")
        found.append(
            ManifestFile(path=path, kind=ManifestKind.IMAGE, label=stem, image=image)
        )
    return found


def find_manifests(deploy: Path) -> list[ManifestFile]:
    """Find every manifest in a deploy directory, best source per image first."""
    images = find_image_manifests(deploy)
    machines = {m.label.removeprefix(f"{m.image}-") for m in images if m.image}
    licenses = find_license_manifests(deploy, machines)

    by_label: dict[str, ManifestFile] = {m.label: m for m in images}
    for manifest in licenses:
        by_label[manifest.label] = manifest
    return sorted(by_label.values(), key=lambda m: m.label)


def parse_image_manifest(path: Path) -> list[Component]:
    """Read a three-column image manifest: `name arch version`."""
    components: list[Component] = []
    text = path.read_text(encoding="utf-8")
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        # Split on the single separator space rather than on runs of
        # whitespace: opkg_query initialises both arch and version to "", so a
        # package missing either field produces "name  version" or "name arch "
        # -- three fields, one of them empty. str.split() would silently see
        # two fields and this would look like a malformed line.
        fields = line.split(" ", 2)
        if len(fields) != 3:
            raise YoctoParseError(
                f"{path}:{lineno}: expected 'name arch version', got {line!r}"
            )
        name, _arch, raw_version = fields
        if not name:
            raise YoctoParseError(f"{path}:{lineno}: empty package name")
        # maxsplit=2 puts everything after the second space in the version.
        # No package version contains a space, so a fourth field means this is
        # not the file we think it is -- and folding it into the version would
        # produce a corrupt purl rather than an error.
        if " " in raw_version.strip():
            raise YoctoParseError(
                f"{path}:{lineno}: version {raw_version.strip()!r} contains a "
                f"space; expected exactly three fields"
            )
        # The architecture is deliberately not carried into the purl: rpm
        # spells it core2_64, deb spells it core2-64, and purl-spec removed
        # `arch` from the yocto type outright. It also adds nothing to
        # identity, since a package name appears at most once per image.
        version = normalize_version(raw_version.strip()) or None
        components.append(
            Component(name=name, version=version, purl=make_purl(name, version))
        )
    return components


def parse_license_manifest(path: Path) -> list[Component]:
    """Read a license.manifest into components.

    Blocks of `KEY: value` lines separated by one blank line, written by
    `write_license_files()` in license_image.bbclass:

        PACKAGE NAME: libcrypto
        PACKAGE VERSION: 3.3.2
        RECIPE NAME: openssl
        LICENSE: Apache-2.0

    The recipe name is kept as a property because it is what a CVE feed
    knows: this image installs `libcrypto`, `openssl-conf` and
    `openssl-ossl-module-legacy`, and all three are openssl.
    """
    components: list[Component] = []
    text = path.read_text(encoding="utf-8")

    # Blocks are separated by a blank line. Splitting on the literal "\n\n"
    # would treat a separator line holding a stray space or tab as ordinary
    # content, silently merging two packages into one record -- and because a
    # block is a dict, the second package's values would quietly win while the
    # first disappeared from the SBOM with a zero exit code.
    blocks: list[list[str]] = []
    current: list[str] = []
    for line in text.splitlines():
        if line.strip():
            current.append(line)
        elif current:
            blocks.append(current)
            current = []
    if current:
        blocks.append(current)

    for lines in blocks:
        fields: dict[str, str] = {}
        for line in lines:
            key, separator, value = line.partition(":")
            if not separator:
                raise YoctoParseError(f"{path}: expected 'KEY: value', got {line!r}")
            key = key.strip()
            if key in fields:
                # Two blocks run together with no separator at all. Last-wins
                # would drop a package without a word.
                raise YoctoParseError(
                    f"{path}: duplicate key {key!r} in one block "
                    f"({fields[key]!r} then {value.strip()!r}); "
                    f"blocks must be separated by a blank line"
                )
            fields[key] = value.strip()

        if "PACKAGE NAME" not in fields:
            # image_license.manifest uses RECIPE NAME / VERSION / LICENSE /
            # FILES and describes deployed artifacts rather than installed
            # packages. Reading it as a package list would be wrong, and
            # keying on "PACKAGE NAME" would silently yield nothing.
            raise YoctoParseError(
                f"{path}: no 'PACKAGE NAME' in block with keys "
                f"{sorted(fields)} -- this looks like an "
                f"image_license.manifest, which lists deployed files"
            )

        name = fields["PACKAGE NAME"]
        if not name:
            raise YoctoParseError(f"{path}: empty PACKAGE NAME")
        version = normalize_version(fields.get("PACKAGE VERSION", "")) or None
        recipe = fields.get("RECIPE NAME") or None

        components.append(
            Component(
                name=name,
                version=version,
                license=fields.get("LICENSE") or None,
                purl=make_purl(name, version),
                properties={"yocto:recipe": recipe} if recipe else {},
            )
        )
    return components


def parse(deploy: Path, *, image: str | None = None) -> tuple[list[Component], str]:
    """Parse one image from a deploy directory.

    Returns the components and the image label to use as the SBOM's root
    component. Where a license manifest and an image manifest describe the
    same image the license manifest is used, because it is the same inventory
    with licenses and recipe names attached.

    A deploy directory holding several images is ambiguous rather than wrong,
    so the caller is told to choose instead of getting a guess.
    """
    manifests = find_manifests(deploy)
    if not manifests:
        raise YoctoParseError(f"no image or license manifest found under {deploy}")

    if image is not None:
        # An exact label wins over a short image name. Without this, a license
        # directory named "core-image-minimal" beside an image manifest for
        # "core-image-minimal-qemux86-64" leaves no string that selects the
        # first: the short name matches both, and the label matches both too.
        exact = [m for m in manifests if m.label == image]
        manifests = exact or [m for m in manifests if m.matches(image)]
        if not manifests:
            raise YoctoParseError(f"no manifest matching {image!r} under {deploy}")

    if len(manifests) > 1:
        # `choice` is the short image name where one could be derived. Where
        # two manifests share it -- a license directory that omits the machine
        # suffix beside an image manifest that has it -- the short names would
        # name the same image twice and neither would select anything.
        short = [m.choice for m in manifests]
        names = short if len(set(short)) == len(short) else [m.label for m in manifests]
        choices = ", ".join(sorted(names))
        raise YoctoParseError(
            f"{deploy} holds several images ({choices}); pick one with --image"
        )

    manifest = manifests[0]
    if manifest.kind is ManifestKind.LICENSE:
        return parse_license_manifest(manifest.path), manifest.label
    return parse_image_manifest(manifest.path), manifest.label

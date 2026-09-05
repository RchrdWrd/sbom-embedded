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

from ..models import Component, has_purl_form, make_purl
from .detect import unreadable_directories


class YoctoParseError(Exception):
    """The deploy directory does not hold what we need to read."""


# How many of a block's keys an error message names before summarising. The
# per-key excerpt bounds one huge key; this bounds a huge number of small ones.
_MAX_KEYS_SHOWN = 8


def _excerpt(text: str, limit: int = 120) -> str:
    """Keep an error message the size of an error message.

    These messages interpolate raw input, and a manifest is allowed to be
    enormous: a single 100 MB line otherwise produces 100 MB of stderr. The
    line number already says where to look.
    """
    if len(text) <= limit:
        return repr(text)
    return f"{text[:limit]!r}... ({len(text)} chars)"


# The rpm backend reports a bare PKGV; deb and ipk both report the control
# file's Version field, which is "[PKGE:]PKGV-PKGR" -- so the same image built
# with PACKAGE_CLASSES=package_ipk yields "1.36.1-r0" where rpm yields
# "1.36.1". PKGR is Yocto's packaging revision and PKGE its epoch; neither is
# part of the upstream version a CVE feed knows. Stripping them is what makes
# the SBOM identical regardless of which backend produced the image.
#
# PKGR is not always "r<N>". bitbake.conf defines it as
# `PKGR ?= "${PR}${EXTENDPRAUTO}"`, and EXTENDPRAUTO is ".${PRAUTO}" whenever a
# PR service is configured -- so "r0" becomes "r0.1", "r0.2" and so on, and a
# local PR server chained to an upstream one mints a dotted subvalue of its
# own ("r0.3.0"). The same shape arrives without any PR service through the
# INC_PR idiom, where a .inc sets INC_PR = "r15" and the recipe sets
# PR = "${INC_PR}.0". Matching only "-r<N>" left those revisions in the
# version, which is exactly the backend-dependent output this normalisation
# exists to prevent.
#
# The trailing "$" and the required digit after "r" are what keep this from
# eating real upstream versions: "1.2-rc1", "1.0-r1a", "1.0-r" and "1.0-r0."
# are all left alone. Legacy PR forms that are not "r<N>[.<N>...]" --
# OE-classic's PR:append = "+gitr${SRCREV}", say -- are deliberately left in
# the version rather than guessed at.
_EPOCH = re.compile(r"^(?P<epoch>\d+):(?P<rest>.*)$")
_REVISION = re.compile(r"-(?P<revision>r\d+(?:\.\d+)*)$")


def normalize_version(raw: str) -> str:
    """Reduce a package-manager version string to the upstream version.

    Removes a leading `<digits>:` epoch and a trailing `-r<N>[.<N>...]`
    packaging revision. The `+git<AUTOINC>+<srcrev>` suffix OE appends to git
    recipes is deliberately kept: it is part of PKGV and identifies the actual
    source revision.
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


def _license_stamp(directory: Path) -> str:
    """The build timestamp for a license directory, or "" if there is none.

    Taken from the directory's own name, and failing that from the name it
    resolves to: the untimestamped directory is normally a symlink to the
    timestamped one bitbake just wrote, so the target carries the stamp its
    own name lacks.
    """
    own = _TIMESTAMPED.search(directory.name)
    if own:
        return own.group()
    try:
        target = _TIMESTAMPED.search(directory.resolve().name)
    except OSError:
        return ""
    return target.group() if target else ""


def _license_mtime(directory: Path) -> float:
    """When the directory last changed, or 0 if that cannot be read."""
    try:
        return directory.stat().st_mtime
    except OSError:
        return 0.0


def _license_rank(directory: Path, depth: int) -> tuple[int, int, str, float]:
    """Order the license directories sharing one label, best last.

    Bitbake writes `<image>-<machine>.rootfs-<DATETIME>/` once per build and
    never removes the old ones -- `licenses/` accumulates exactly the way
    `images/` does -- then points a stable symlink at the build it just
    finished. So a deploy directory that has been built twice holds two
    `license.manifest` files under the same label, and they do not agree.

    Ranked by four things, in order:

    * **Depth.** The `licenses/<arch>/` level was added in Yocto 4.3, so a tree
      carrying both layouts was upgraded in place and the deeper directory is
      the one a newer bitbake wrote. Without this, two untimestamped
      directories -- a pre-4.3 symlink and a current one -- tie, and the glob
      order hands back the older layout.
    * **Whether the name carries a timestamp.** The untimestamped name is the
      symlink, which is the build system's own statement of which image is
      current, so it outranks every timestamped directory at its own depth --
      including a newer one, which is what a build that wrote its licenses and
      then failed leaves behind.
    * **The timestamp**, from the name or from the symlink's target. Plain
      string order, because DATETIME is `%Y%m%d%H%M%S`.
    * **Modification time.** Only reachable when two directories at one depth
      are both untimestamped and neither resolves to a stamped name -- a copy
      that flattened the symlinks, after an `SSTATE_PKGARCH` rename. There is
      nothing left in the names to go on, and mtime is at least the build's
      own signal rather than alphabetical order over arch directories.
    """
    untimestamped = 0 if _TIMESTAMPED.search(directory.name) else 1
    return (depth, untimestamped, _license_stamp(directory), _license_mtime(directory))


def find_license_manifests(deploy: Path, machines: set[str]) -> list[ManifestFile]:
    """Locate every `license.manifest` under a deploy directory.

    The arch level in `licenses/<arch>/<image>-<machine>/` was added in Yocto
    4.3, so both depths are searched. `image_license.manifest` is deliberately
    not picked up: it describes deployed artifacts, not installed packages.

    Where several directories describe the same image -- an accumulated
    rebuild, a pre-4.3 layout left beside a current one, a renamed arch
    directory -- the most recent is used; see `_license_rank`.
    """
    found: dict[str, ManifestFile] = {}
    ranks: dict[str, tuple[int, int, str, float]] = {}
    licenses = deploy / "licenses"
    for depth, pattern in enumerate(("*/license.manifest", "*/*/license.manifest"), 1):
        for path in sorted(licenses.glob(pattern)):
            label = _license_label(path.parent)
            rank = _license_rank(path.parent, depth)
            # Keeping whichever path sorted first looks harmless while the only
            # collision is a symlink and its own target, which hold the same
            # file. Across two builds it is not: timestamps sort
            # chronologically, so first-wins deterministically returns the
            # OLDEST build's package list -- complete, plausible, schema-valid,
            # and describing firmware that is no longer the one on disk.
            if label in found and rank <= ranks[label]:
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
            ranks[label] = rank
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

    # An image left with only its image manifest will be described with no
    # licenses and no recipe names. That is correct for a build that kept no
    # `licenses/` -- and indistinguishable from one whose `licenses/` we were
    # simply not allowed to read, because `Path.glob` reports a directory it
    # may not open as no matches rather than as an error.
    #
    # Checked here rather than inside `find_license_manifests`, which cannot
    # see whether a fallback is about to happen: gating on "no license manifest
    # anywhere" masked the ordinary layout, where one image's readable
    # directory hides another image's blocked one.
    if any(m.kind is ManifestKind.IMAGE for m in by_label.values()):
        # depth=4: the manifest sits at licenses/<arch>/<image-dir>/ since
        # Yocto 4.3, so four levels -- licenses, <arch>, <image-dir> and the
        # walk's own root -- have to be listable to rule the pattern out.
        read = {manifest.label for manifest in licenses}
        blocked = [
            directory
            for directory in unreadable_directories(deploy / "licenses", depth=4)
            # A stale rebuild directory nobody can read does not matter once
            # this image's current one has been read successfully.
            if _license_label(directory) not in read
        ]
        if blocked:
            listed = ", ".join(str(directory) for directory in blocked)
            raise YoctoParseError(
                f"{deploy / 'licenses'}: no license.manifest for every image, "
                f"and these directories could not be read: {listed}"
            )

    return sorted(by_label.values(), key=lambda m: m.label)


def _read(path: Path) -> str:
    """Read a manifest, turning read failures into our own error type.

    Without this, a non-UTF-8 byte, an unreadable file or a dangling symlink
    escapes as a traceback instead of the documented `error: ...` line.
    """
    try:
        # utf-8-sig, matching buildroot.py: a BOM left by an editor decodes to a
        # literal U+FEFF, which is category Cf rather than whitespace, so
        # `strip()` keeps it and it becomes part of the first package's name.
        # The image-manifest path would then emit that package with a purl
        # nothing can resolve, at exit 0.
        return path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as err:
        raise YoctoParseError(f"{path}: cannot read: {err}") from err


def parse_image_manifest(path: Path) -> list[Component]:
    """Read a three-column image manifest: `name arch version`."""
    components: list[Component] = []
    text = _read(path)
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
                f"{path}:{lineno}: expected 'name arch version', got {_excerpt(line)}"
            )
        name, _arch, raw_version = fields
        # Not `if not name`: a name of only tabs or non-breaking space is
        # truthy, and packageurl then fails with an opaque TypeError naming
        # neither the file nor the line.
        if not name.strip():
            raise YoctoParseError(f"{path}:{lineno}: empty package name")
        if not has_purl_form(name):
            # Blank is not the only unusable name: packageurl reduces one made
            # only of slashes to nothing and then dies with a TypeError that
            # names neither the file nor the line.
            raise YoctoParseError(
                f"{path}:{lineno}: package name {_excerpt(name)} has no purl form"
            )
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
    text = _read(path)

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
                raise YoctoParseError(
                    f"{path}: expected 'KEY: value', got {_excerpt(line)}"
                )
            key = key.strip()
            if key in fields:
                # Two blocks run together with no separator at all. Last-wins
                # would drop a package without a word.
                raise YoctoParseError(
                    f"{path}: duplicate key {_excerpt(key)} in one block "
                    f"({_excerpt(fields[key])} then {_excerpt(value.strip())}); "
                    f"blocks must be separated by a blank line"
                )
            fields[key] = value.strip()

        if "PACKAGE NAME" not in fields:
            # image_license.manifest uses RECIPE NAME / VERSION / LICENSE /
            # FILES and describes deployed artifacts rather than installed
            # packages. Reading it as a package list would be wrong, and
            # keying on "PACKAGE NAME" would silently yield nothing.
            # Every key is an arbitrary prefix of an input line, so each goes
            # through _excerpt like every other interpolation here. The count
            # is bounded too: excerpting each key caps one enormous line, but a
            # block with thousands of short keys still produced hundreds of
            # kilobytes of stderr from the sum.
            names = sorted(fields)
            shown = ", ".join(_excerpt(key) for key in names[:_MAX_KEYS_SHOWN])
            keys = (
                shown
                if len(names) <= _MAX_KEYS_SHOWN
                else f"{shown}, ... ({len(names)} keys)"
            )
            raise YoctoParseError(
                f"{path}: no 'PACKAGE NAME' in block with keys "
                f"[{keys}] -- this looks like an "
                f"image_license.manifest, which lists deployed files"
            )

        name = fields["PACKAGE NAME"]
        if not name:
            raise YoctoParseError(f"{path}: empty PACKAGE NAME")
        if not has_purl_form(name):
            raise YoctoParseError(
                f"{path}: PACKAGE NAME {_excerpt(name)} has no purl form"
            )
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
        # depth=2: the manifest sits at images/<machine>/, so the <machine>
        # level has to be listable. depth=1 could only ever list images/ itself.
        blocked = unreadable_directories(
            deploy / "images", depth=2
        ) + unreadable_directories(deploy / "licenses", depth=4)
        if blocked:
            listed = ", ".join(str(directory) for directory in blocked)
            raise YoctoParseError(
                f"no image or license manifest found under {deploy}; these "
                f"directories could not be read: {listed}"
            )
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

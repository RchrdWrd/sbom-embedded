"""Work out which build system produced a directory.

The user should not have to know, and more to the point should not have to
remember, whether a given directory is a Yocto deploy tree or a Buildroot
output tree.

Both are recognised by the presence of an artifact a parser would go on to
read, which rules out the obvious false positive: an empty `images/` directory
is not a Yocto build. It is an existence check, not a parse, so it does not
promise the parser will then succeed -- a deploy holding only timestamped
manifests, a zero-byte manifest.csv, or several images and no `--image` all
detect and then fail in the parser.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class DetectionError(Exception):
    """Nothing recognisable was found."""


class BuildSystem(StrEnum):
    YOCTO = "yocto"
    BUILDROOT = "buildroot"


@dataclass(frozen=True)
class Detected:
    """What was found, and the directory the matching parser should be given."""

    system: BuildSystem
    root: Path


# Where each build system's evidence sits, relative to what the user typed.
# The nested entries let someone point at the top of a build tree instead of
# hunting for the exact subdirectory.
_YOCTO_PROBES = (
    Path(),
    Path("tmp/deploy"),
    Path("build/tmp/deploy"),
)
_BUILDROOT_PROBES = (
    Path(),
    Path("legal-info"),
    Path("output/legal-info"),
)

# A deploy directory is recognised by an artifact a parser can actually read.
# Either alone is enough: a build that kept its licenses but not its images is
# still readable, and so is the reverse.
_YOCTO_EVIDENCE = (
    "images/*/*.manifest",
    "licenses/*/license.manifest",
    "licenses/*/*/license.manifest",
)


def unreadable_directories(root: Path, depth: int) -> list[Path]:
    """Directories at or under `root` whose contents could not be listed.

    `Path.glob` reports a directory it is not allowed to read as no matches
    rather than as an error, so "there is nothing here" and "I was not allowed
    to look" are indistinguishable until asked directly. Only called once
    discovery has come up empty, so the cost is paid on the error path alone.
    """
    blocked: list[Path] = []

    def walk(parent: Path, remaining: int) -> None:
        try:
            children = sorted(child for child in parent.iterdir() if child.is_dir())
        except FileNotFoundError:
            return
        except OSError:
            blocked.append(parent)
            return
        if remaining > 1:
            for child in children:
                walk(child, remaining - 1)

    walk(root, depth)
    return blocked


def _yocto_root(start: Path) -> Path | None:
    for probe in _YOCTO_PROBES:
        deploy = start / probe
        if not deploy.is_dir():
            continue
        # `is not None` rather than a bare truth test: glob yields Path
        # objects, and relying on their truthiness would read as a check on
        # the path's contents rather than on whether one was found at all.
        if any(
            next(deploy.glob(pattern), None) is not None for pattern in _YOCTO_EVIDENCE
        ):
            return deploy
    return None


def _buildroot_root(start: Path) -> Path | None:
    for probe in _BUILDROOT_PROBES:
        directory = start / probe
        if (directory / "manifest.csv").is_file():
            return directory
    return None


def detect(root: Path) -> Detected:
    """Decide which build system produced `root`.

    Raises if nothing is found, or if both are -- guessing between two real
    build trees would silently drop half the components.
    """
    if not root.exists():
        raise DetectionError(f"{root} does not exist")
    if not root.is_dir():
        raise DetectionError(f"{root} is not a directory")

    yocto = _yocto_root(root)
    buildroot = _buildroot_root(root)

    if yocto and buildroot:
        raise DetectionError(
            f"{root} looks like both a Yocto deploy directory ({yocto}) and a "
            f"Buildroot output directory ({buildroot}); point at one of them"
        )
    if yocto:
        return Detected(BuildSystem.YOCTO, yocto)
    if buildroot:
        return Detected(BuildSystem.BUILDROOT, buildroot)

    # A directory we were not allowed to read looks exactly like an empty one
    # to glob, so "found nothing" would otherwise send the user hunting for
    # files that are sitting right there.
    # depth=4 because the deepest evidence pattern is
    # licenses/<arch>/<image>/license.manifest: the file sits three directory
    # levels below the probe root, so four directories -- the root, licenses,
    # <arch> and <image> -- all have to be listable to rule it out. The walk
    # attempts iterdir() at levels 0..depth-1.
    blocked = [
        directory
        for probe in (*_YOCTO_PROBES, *_BUILDROOT_PROBES)
        for directory in unreadable_directories(root / probe, depth=4)
    ]
    if blocked:
        listed = ", ".join(sorted({str(directory) for directory in blocked}))
        raise DetectionError(
            f"{root} holds no manifest this tool can read, and these "
            f"directories could not be read: {listed}"
        )
    raise DetectionError(
        f"{root} is neither a Yocto deploy directory nor a Buildroot output "
        f"directory: looked for images/*/*.manifest, licenses/*/license.manifest "
        f"and legal-info/manifest.csv"
    )

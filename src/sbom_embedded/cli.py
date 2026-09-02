"""Command line entry point."""

from __future__ import annotations

import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from . import __version__
from .parsers import buildroot, yocto
from .parsers.detect import BuildSystem, DetectionError, detect
from .writer import to_json

app = typer.Typer(
    add_completion=False,
    help="Generate a CycloneDX SBOM from Yocto or Buildroot build output.",
)


class Format(StrEnum):
    CYCLONEDX = "cyclonedx"


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"sbom-embedded {__version__}")
        raise typer.Exit()


@app.command()
def main(
    path: Annotated[
        Path,
        typer.Argument(
            help="A Yocto deploy directory or a Buildroot output directory.",
            show_default=False,
        ),
    ],
    output_format: Annotated[
        Format,
        typer.Option("--format", help="Output format."),
    ] = Format.CYCLONEDX,
    image: Annotated[
        str | None,
        typer.Option(
            "--image",
            help="Which image to describe, when a Yocto deploy holds several.",
            show_default=False,
        ),
    ] = None,
    name: Annotated[
        str | None,
        typer.Option(
            "--name",
            help=(
                "Name for the product being described. Defaults to the "
                "manifest label (core-image-minimal-qemux86-64, or "
                "'buildroot')."
            ),
            show_default=False,
        ),
    ] = None,
    product_version: Annotated[
        str | None,
        typer.Option(
            "--product-version",
            help=(
                "Version of the product being described. Left out of the SBOM "
                "when not given -- no manifest records it."
            ),
            show_default=False,
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Write here instead of stdout.",
            show_default=False,
        ),
    ] = None,
    _version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Read an existing build's manifests and write a CycloneDX SBOM."""
    try:
        found = detect(path)
        if found.system is BuildSystem.YOCTO:
            components, label = yocto.parse(found.root, image=image)
        elif found.system is BuildSystem.BUILDROOT:
            if image is not None:
                raise typer.BadParameter(
                    "--image applies to Yocto builds; a Buildroot manifest "
                    "describes a single target."
                )
            components, label = buildroot.parse(found.root)
        else:  # a BuildSystem member was added without a parser
            raise DetectionError(f"no parser for {found.system}")
    except (
        DetectionError,
        yocto.YoctoParseError,
        buildroot.BuildrootParseError,
    ) as err:
        typer.secho(f"error: {err}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from err

    if not components:
        # A valid, empty SBOM is the worst possible compliance artifact: it
        # looks like a clean result. Still emit it -- the caller asked -- but
        # never let it pass without a word.
        typer.secho(
            f"warning: no packages found in {path}; the SBOM will be empty",
            fg=typer.colors.YELLOW,
            err=True,
        )

    # product_version stays None unless the user supplies it. No manifest
    # carries a product version, so anything else would be invented.
    document = to_json(
        components,
        product_name=name or label,
        product_version=product_version,
    )

    if output is None:
        # Deliberately not typer.echo: the SBOM is data on stdout, and the
        # documented usage pipes it into a file. The trailing newline makes
        # the redirected file a well-formed text file.
        sys.stdout.write(document + "\n")
    else:
        try:
            output.write_text(document + "\n", encoding="utf-8")
        except OSError as err:
            typer.secho(
                f"error: cannot write {output}: {err}", fg=typer.colors.RED, err=True
            )
            raise typer.Exit(code=1) from err
        typer.secho(
            f"wrote {len(components)} components to {output}",
            fg=typer.colors.GREEN,
            err=True,
        )

# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-09-05

Documentation only. No code changes; the 0.1.0 artifacts behave identically.

### Fixed

- The install instructions on the PyPI page told readers to install from git,
  because 0.1.0's README was written before the package was on PyPI. They now
  lead with `pipx run sbom-embedded` and `uvx sbom-embedded`, with the git
  form kept for running unreleased changes. A PyPI release's README cannot be
  edited after upload, so correcting it needs a release.
- Relative links in the README (`DESIGN.md`, `LICENSE`, `PROVENANCE.md`) are
  now absolute. PyPI does not resolve relative links against the repository
  the way GitHub does, so they pointed nowhere on the project page.

- The README carried a `Releasing` section: PyPI publisher setup and tagging
  instructions. That is maintainer documentation, and the README is the PyPI
  landing page, so it was telling every user how to configure a publisher for
  a project they do not own. Moved to `CONTRIBUTING.md`.

### Added

- `CONTRIBUTING.md`, covering setup, the rule that fixtures are real build
  output, and the release process.
- A PyPI version badge, and the tested Python range stated explicitly.

## [0.1.0] - 2026-09-02

First release.

### Added

- CycloneDX 1.6 SBOM generation from Yocto and Buildroot build output, reading
  manifests a finished build already wrote. No build is started.
- Yocto: reads `licenses/**/license.manifest` where present -- it carries
  licenses and recipe names -- and falls back to
  `images/<machine>/*.rootfs.manifest` otherwise.
- Buildroot: reads `legal-info/manifest.csv`, locating columns by header name
  so six- and seven-column eras both parse.
- Automatic build-system detection from the directory, refusing to guess when
  a directory looks like both or holds several images.
- `--image`, `--name`, `--product-version`, `--output` and `--format`.
- Every component carries a `pkg:generic` purl by construction.
- A `yocto:recipe` property mapping each package back to the recipe that
  produced it, where a license manifest is available.

### Notes

- Package revisions (`-r0`) and epochs are stripped from Yocto versions so the
  same image yields the same SBOM whichever package backend built it.
- Buildroot's `custom` and `unknown` placeholders become absent fields rather
  than invented data. No CPEs, suppliers or hashes are generated.
- A `pkg:generic` purl is not resolved to a vulnerability namespace by Grype,
  Trivy or Dependency-Track. See the README before trusting a clean scan.

[Unreleased]: https://github.com/RchrdWrd/sbom-embedded/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/RchrdWrd/sbom-embedded/releases/tag/v0.1.1
[0.1.0]: https://github.com/RchrdWrd/sbom-embedded/releases/tag/v0.1.0

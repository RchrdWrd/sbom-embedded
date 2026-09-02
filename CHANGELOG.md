# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/RchrdWrd/sbom-embedded/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/RchrdWrd/sbom-embedded/releases/tag/v0.1.0

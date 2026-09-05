# sbom-embedded

[![CI](https://github.com/RchrdWrd/sbom-embedded/actions/workflows/ci.yml/badge.svg)](https://github.com/RchrdWrd/sbom-embedded/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](https://github.com/RchrdWrd/sbom-embedded/blob/main/pyproject.toml)
[![PyPI](https://img.shields.io/pypi/v/sbom-embedded)](https://pypi.org/project/sbom-embedded/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](https://github.com/RchrdWrd/sbom-embedded/blob/main/LICENSE)

Generate a CycloneDX SBOM from a Yocto or Buildroot build you have already
run, by reading the manifest files the build wrote — no rebuild, no bitbake,
under a tenth of a second.

The EU Cyber Resilience Act (2024/2847) requires device manufacturers to keep
a machine-readable component list for their products. Syft, Trivy and cdxgen
are good at containers and npm and weak at embedded Linux build systems. This
fills that gap.

## Install and run

Without installing anything permanently:

```bash
pipx run sbom-embedded ./output > sbom.json
```

```bash
uvx sbom-embedded ./output > sbom.json
```

Or install it:

```bash
pipx install sbom-embedded
```

To run an unreleased change straight from the repository, point the same
commands at git instead:

```bash
pipx run --spec git+https://github.com/RchrdWrd/sbom-embedded sbom-embedded ./output
uvx --from git+https://github.com/RchrdWrd/sbom-embedded sbom-embedded ./output
```

Python 3.11 or newer, tested on 3.11 through 3.14. The tool only reads files,
so it runs anywhere Python does.

## Usage

Point it at a build directory. It works out which build system produced it —
you do not have to say.

```bash
sbom-embedded ./build/tmp/deploy > sbom.json    # Yocto
sbom-embedded ./output > sbom.json              # Buildroot
```

A path to Buildroot's `manifest.csv` works too, if that is what you have to
hand. `-o` replaces its destination atomically, so a failed run leaves the
previous SBOM where it was rather than a truncated one.

| Option | Meaning |
| --- | --- |
| `--format` | Output format. `cyclonedx` is the only one. |
| `--image` | Which image to describe, when a Yocto deploy holds several. |
| `--name` | Name for the product. Defaults to the image name, or `buildroot`. |
| `--product-version` | Version of the product. Omitted from the SBOM if not given. |
| `--output`, `-o` | Write to a file instead of stdout. |

### Real output

Run against a Buildroot manifest in this repository:

```console
$ sbom-embedded tests/fixtures/buildroot-2023.02
{
  "components": [
    {
      "bom-ref": "pkg:generic/busybox@1.36.1",
      "licenses": [
        {
          "license": {
            "name": "GPL-2.0, bzip2-1.0.4"
          }
        }
      ],
      "name": "busybox",
      "purl": "pkg:generic/busybox@1.36.1",
      "type": "library",
      "version": "1.36.1"
    },
    ...
```

If a Yocto deploy directory holds more than one image, it stops and lists them
rather than picking one:

```console
$ sbom-embedded tests/fixtures/yocto-6.0.2
error: tests/fixtures/yocto-6.0.2 holds several images (core-image-full-cmdline,
core-image-minimal); pick one with --image
```

### On a real Buildroot build

Verified end to end on Buildroot `2026.08-rc3-28-g79fd6241e4`:

```bash
git clone https://gitlab.com/buildroot.org/buildroot.git
cd buildroot
make qemu_x86_64_defconfig
make legal-info          # downloads sources, does not compile: 10-30 min
sbom-embedded ./output -o sbom.json
```

```console
$ sbom-embedded ./output -o sbom.json
wrote 44 components to sbom.json
```

44 components in **0.09 s**; all 44 carry a purl, a version and a license; 26
distinct license expressions; the document validates against the CycloneDX 1.6
schema. That build's manifest is committed as
`tests/fixtures/buildroot-2026.08/` — see
[PROVENANCE.md](https://github.com/RchrdWrd/sbom-embedded/blob/main/tests/fixtures/PROVENANCE.md).

> **Ubuntu 25.10 and newer:** `make legal-info` refuses to start with
> *"You have an uutils 'install' version installed"*, because those releases
> ship uutils coreutils rather than GNU coreutils. You can fix it system-wide
> with `sudo update-alternatives --install /usr/bin/install install /usr/bin/gnuinstall 100`,
> or just for one build without touching the system:
>
> ```bash
> mkdir -p /tmp/gnushim && ln -sf /usr/bin/gnuinstall /tmp/gnushim/install
> PATH=/tmp/gnushim:$PATH make legal-info
> ```

## Read this before you scan the output

**A vulnerability scan of this SBOM can report zero findings while the
firmware is full of known vulnerabilities.** This is not a hypothetical.

Every component gets a `pkg:generic/<name>@<version>` purl. Neither Yocto nor
Buildroot packages exist in any ecosystem repository, so there is no better
purl type available. But Grype, Trivy and Dependency-Track do not resolve
`pkg:generic` to a vulnerability namespace — they reach the NVD through CPEs,
which this tool does not emit, because a CPE would be a guess about vendor and
product strings rather than something any manifest records.

Measured, not assumed. The SBOM from the real Buildroot build above, scanned
with Grype 0.118.0:

```console
$ grype sbom:sbom.json
No vulnerabilities found
```

The same five packages, with CPEs added by hand purely to demonstrate the
difference:

```console
NAME     INSTALLED  TYPE            VULNERABILITY   SEVERITY  EPSS         RISK
busybox  1.38.0     UnknownPackage  CVE-2026-38754  High      0.4% (33rd)  0.3
busybox  1.38.0     UnknownPackage  CVE-2026-38755  High      0.3% (27th)  0.2
busybox  1.38.0     UnknownPackage  CVE-2026-38753  High      0.2% (15th)  0.2
```

Same document, same packages, same scanner. The difference is the identifier,
not the firmware.

So: use this SBOM as a component inventory and a compliance record. **Do not
read a clean Grype run on it as evidence that the firmware is clean.** For
vulnerability matching you need a tool that maps package names to CPEs, or a
scanner configured for these package names specifically.

## How much of this is verified on real builds

Both paths have been walked from a build to an SBOM on real hardware, not
from fixtures alone.

**Buildroot.** A real `make legal-info` on Buildroot 2026.08-rc3 produced the
44-package manifest shown above, and a real `make` produced a complete output
tree of 867,355 files. That tree turned out to contain ten files named
`*.manifest` — all of them Windows application manifests inside host package
sources (host-python3, host-cmake, host-ninja, gcc). None sits at
`images/<dir>/*.manifest`, which is the only reason Yocto detection does not
fire on a Buildroot tree; there is a test pinning that.

**Yocto.** `bitbake core-image-minimal` was run to completion for qemux86-64
on the Yocto 6.0.2 release revisions, and the tool was run against the
`tmp/deploy` directory it wrote:

```console
$ sbom-embedded ./deploy -o sbom.json
wrote 39 components to sbom.json
```

39 components in 0.09 s, every one with a purl, a license and a `yocto:recipe`
property, validating against the CycloneDX 1.6 schema. That deploy tree is
committed as `tests/fixtures/yocto-6.0.2-live/`.

The same image was then rebuilt with `PACKAGE_CLASSES = "package_ipk"`. That
matters because every other fixture here comes from an rpm-backend build, and
rpm is the one backend whose version column carries no package revision. In
the ipk manifest all 38 rows do (`busybox 1.37.0-r0`), two carry `-r1`, and
`netbase all 1:6.5-r0` carries an epoch. The tool strips all of that, so the
37 purls the two images share are byte-identical: **the same firmware
described the same way regardless of how it was packaged.** Both manifests are
committed, and a test compares them.

It is the only fixture holding both manifest kinds from a single build, which
makes it the one that demonstrates why they must never be joined by package
name: the image manifest lists 37 packages, the license manifest 39, and 11 of
the 37 names have no counterpart on the other side — `libc6` against `glibc`,
`libz1` against `zlib`, `libcrypto3` against `libcrypto`, and so on.

> **Building Yocto on a current host:** the 6.0.2 release works, but the
> 5.0.9 release does not — its bitbake crashes on Python 3.14, and its
> `UNINATIVE_MAXGLIBCVERSION` is below a current glibc. Configuring
> `SSTATE_MIRRORS` against `sstate.yoctoproject.org` is what makes the build
> practical: 373 of 396 wanted objects came from the mirror, so it fit on a
> machine with 7 GB of free disk instead of needing 20-40.

## Known limitations

* **Yocto builds without a license manifest produce no licenses.** The image
  manifest has no license column. If your build kept
  `tmp/deploy/licenses/`, that is read instead and you get licenses and recipe
  names; otherwise you get names, versions and purls only. Buildroot always
  carries licenses.
* **Package names are not upstream project names.** Your firmware contains
  `libcrypto`, `openssl-conf` and `openssl-ossl-module-legacy`; a CVE database
  knows `openssl`. Where a Yocto license manifest is read, the recipe behind
  each package is recorded as a `yocto:recipe` property. Where only the image
  manifest exists, the names are the Debian-renamed forms (`libc6`, `libz1`)
  with no way back.
* **License strings are copied, not normalised.** Yocto writes
  `GPL-2.0-only & MIT` and Buildroot `GPL-2.0+ (programs), LGPL-2.1+` — neither
  is a valid SPDX expression. Valid SPDX identifiers and expressions are
  emitted as such; everything else is emitted as a named license, verbatim.
  Nothing is guessed at or dropped.
* **No supplier and no hashes.** Neither build system records a supplier or a
  per-package hash, so those fields are absent rather than invented.
* **Large images are slow.** The CycloneDX library re-derives the dependency
  graph while serialising, at a cost that grows with the square of the package
  count: the 44-package build above renders in 0.09 s, but 2000 packages take
  around 20 seconds and 4000 around a minute. The parsing is milliseconds
  either way.
* **The dependency graph is flat.** Every package hangs off the image. The
  Yocto manifests carry no inter-package dependencies. Buildroot's
  `DEPENDENCIES WITH LICENSES` column does — it is the one place real edges
  are available — and it is read past rather than emitted.
* **Buildroot `SOURCE ARCHIVE`, `SOURCE SITE`, `LICENSE FILES` and
  `DEPENDENCIES WITH LICENSES` are not emitted.**
* **The product name and version are yours to supply.** A Buildroot manifest
  carries no product identity, so the root component is named `buildroot`
  unless you pass `--name`, and has no version unless you pass
  `--product-version`. Nothing is invented to fill them.

The underlying reasoning, and the manifest formats in detail, are in
[DESIGN.md](https://github.com/RchrdWrd/sbom-embedded/blob/main/DESIGN.md).

## Development

```bash
uv sync
uv run pytest
```

Without `uv`:

```bash
python3 -m venv .venv
.venv/bin/pip install -e . --group dev   # needs pip 25.1+ for --group
.venv/bin/python -m pytest
```

133 tests. Most of the wall-clock is one test that renders 1000 components
and three that spawn a subprocess; the parser tests are milliseconds. They run
from fixture files under
`tests/fixtures`, never from a live build. Every fixture is unmodified output
from a real Yocto or Buildroot build —
[PROVENANCE.md](https://github.com/RchrdWrd/sbom-embedded/blob/main/tests/fixtures/PROVENANCE.md) records where each came from and
what it is kept for. The format details matter too much to mock.

How to contribute, and how a release is cut, are in
[CONTRIBUTING.md](https://github.com/RchrdWrd/sbom-embedded/blob/main/CONTRIBUTING.md).

## License

MIT — see [LICENSE](https://github.com/RchrdWrd/sbom-embedded/blob/main/LICENSE).

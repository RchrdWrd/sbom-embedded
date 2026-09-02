# sbom-embedded — design and behaviour

Reference document for reviewing this codebase. It describes what the tool
does, how each part works, and *why* each non-obvious decision was made. It is
self-contained: you should not need to read the source to follow it.

Every checkable claim here has been verified against the source or by running
the code. Where a statement comes from outside this repository it says so.

Version described: 0.1.0. Python 3.11+. Runtime dependencies: `typer`,
`cyclonedx-python-lib`, `packageurl-python`. 92 tests, ~1.5 s.

---

## 1. Purpose and scope

Generate a CycloneDX SBOM from a Yocto or Buildroot build that has **already
run**, by reading the manifest files the build wrote.

The EU Cyber Resilience Act (2024/2847) requires device manufacturers to keep
a machine-readable component list. Syft, Trivy and cdxgen handle containers
and language ecosystems well and embedded Linux build systems poorly.

### Hard constraints the design is built around

| Constraint | Consequence in the code |
| --- | --- |
| **Never start a build.** | Only file reads. No subprocess, no bitbake, no `make`. Runs in ~0.1 s, not ~6 h. |
| **One core, two thin adapters.** | Parsers return `(list[Component], label)`. CycloneDX is written once, in `writer.py`; no parser imports a CycloneDX type (verified by grep). |
| **`purl` is mandatory.** | `Component.__post_init__` derives one if the parser did not supply it. A component without a purl is invisible to every CVE matcher, which would make the tool pointless. |

### Explicitly out of scope

Binary firmware analysis; CVE matching or vulnerability monitoring; SPDX
output; a plugin system for further build systems; web UI, database, user
management. None of these are stubbed or half-present.

---

## 2. Architecture

```
                    ┌──────────────┐
   directory  ──►   │  detect()    │  → Detected(system, root)
                    └──────┬───────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
      ┌───────────────┐         ┌───────────────┐
      │ parsers/yocto │         │ parsers/      │
      │               │         │   buildroot   │
      └───────┬───────┘         └───────┬───────┘
              │                         │
              └──────────┬──────────────┘
                         ▼
           (list[Component], label)   ← Component is the only shared structure;
                         │              the label names the root component
                         ▼
                 ┌───────────────┐
                 │   writer.py   │  CycloneDX 1.6 JSON
                 └───────────────┘
```

| File | Responsibility |
| --- | --- |
| `models.py` | `Component` dataclass, `make_purl()` |
| `parsers/detect.py` | Directory → build system + the directory to parse |
| `parsers/yocto.py` | Yocto image manifest and license manifest |
| `parsers/buildroot.py` | Buildroot `legal-info/manifest.csv` |
| `writer.py` | `list[Component]` → CycloneDX JSON string |
| `cli.py` | Typer command, error handling, exit codes |

**Adding a build system** means: a new parser module; a `BuildSystem` member
plus a probe list, an evidence list and a root-finder in `detect.py`
(and its two-way ambiguity check becomes an n-way one); and a dispatch arm in
`cli.py`. Nothing in `writer.py` changes.

---

## 3. The `Component` model

```python
@dataclass(slots=True)
class Component:
    name: str
    version: str | None = None
    supplier: str | None = None
    license: str | None = None
    hash: str | None = None
    purl: str | None = None
    properties: dict[str, str] = field(default_factory=dict)
```

* **`name`** is the only field every format guarantees. Empty raises
  `ValueError`.
* **`version`** is optional on purpose. Some real packages genuinely have no
  version (Buildroot's `custom` placeholder), and a purl is valid without one.
* **`supplier`** is never populated by either parser. Neither build system
  records a per-package supplier.
* **`hash`** is a composite string, `"sha256:<hex>"`. Never populated —
  neither manifest format carries per-package hashes.
* **`purl`** — `__post_init__` fills it in when `purl is None`. Note that both
  parsers already pass an explicit `purl=make_purl(name, version)` with the
  same arguments, so **this fallback never fires in production**; it is a
  safety net for future callers, exercised only by tests. The guard is
  `is None`, so an explicit empty string would survive it.
* **`properties`** was added when the Yocto license manifest turned out to
  carry the recipe name, which has no natural home among the other fields. A
  deliberately generic escape hatch keyed by a namespaced name
  (`yocto:recipe`), so build-system-specific provenance does not force a
  build-system-specific field into the shared core.

### purl construction

`make_purl(name, version, *, qualifiers=None)` builds the string with
`packageurl-python` — never string concatenation, so escaping is correct
(`+` becomes `%2B`). Falsy qualifier values are dropped.

**Every purl the tool actually emits is `pkg:generic/<name>@<version>`.** All
three production call sites pass only name and version. The `qualifiers`
parameter exists and is exercised by a writer test; nothing in the pipeline
uses it. See §7.2 and §7.3 for why.

**Why `generic`.** Neither Yocto nor Buildroot packages are published to any
ecosystem repository. The purl spec has since gained a `yocto` type, and
OE-Core master emits `pkg:yocto/<layer>/<bpn>@<pv>` — but that needs the
recipe name (BPN), recipe version (PV) and layer name. An image manifest
supplies none of those: it has the *package* name and *package* version
(`libc6`, not `glibc`), and no layer information at all. Emitting `pkg:yocto`
from data that cannot fill it would produce purls that do not match Yocto's
own output, which is the only reason to use that type.

---

## 4. Input format 1 — Yocto image manifest

**Location:** `images/<machine>/<image>-<machine>.rootfs.manifest`
(the `.rootfs` infix appeared in Yocto 4.3; older releases omit it).

**Written by** `write_image_manifest` in `rootfs-postcommands.bbclass`, via
`format_pkg_list(pkgs, "ver")` in `meta/lib/oe/utils.py`:

```python
output.append("%s %s %s" % (pkg, pkg_dict[pkg]["arch"], pkg_dict[pkg]["ver"]))
```

**Format:** three fields, exactly one space between them, no header, no
quoting, no comments, sorted by package name. A non-empty file ends in one
newline; an image with no packages yields a zero-byte file.

```
base-files qemux86_64 3.0.14
busybox x86_64_v3 1.37.0
kernel-6.18.24-yocto-standard qemux86_64 6.18.24+git0+f94e250f9b_b1ba542851
```

**Column 1** is the runtime *package* name (bitbake `PKG`), after
`debian.bbclass` renaming — so `libz1`, not `zlib`; `libc6`, not `glibc`. One
recipe routinely produces many rows (`busybox` → `busybox`,
`busybox-hwclock`, `busybox-syslog`, `busybox-udhcpc`).

**Column 3 differs by package backend.** This is the single most important
fact about the format:

| Backend | Version column | Source |
| --- | --- | --- |
| rpm | bare `PKGV` — `1.36.1` | `dnf repoquery --queryformat "... %{version} ..."` — the RPM `Version` tag only |
| deb, ipk | `[PKGE:]PKGV-PKGR` — `1.36.1-r0`, `2:1.36.1-r0` | the control file `Version:` field, via `opkg_query` |

**There is no license column.** A build that kept only its image manifests
produces an SBOM with no license information at all.

### Parsing decisions

**Split on the single separator space, not on whitespace runs.**
`opkg_query` initialises both `arch` and `ver` to `""`, so a package missing
either field emits `name  version` (two spaces) or `name arch ` (trailing
space). `str.split()` would see two fields and report a malformed line;
`line.split(" ", 2)` correctly yields three fields, one empty. The whole line
is therefore never stripped — only blank lines are skipped.

`maxsplit=2` would otherwise fold a fourth field into the version, silently
producing `pkg:generic/busybox@1.36.1%20extra`. No package version contains a
space, so a version containing one is rejected with an error naming the line.

**Which files are considered.** The glob is `images/*/*.manifest`, so it
descends exactly one machine directory. SDK manifests (`deploy/sdk/`) are
never reached — not filtered, simply out of scope of the glob.

A file whose stem does not end in `-<machine>` is skipped. That is what
excludes Yocto's timestamped copy (`...rootfs-20250610090225.manifest`) in
favour of the stable symlink beside it, so packages are never counted twice.
It also excludes `...rootfs-dbg.manifest`. Note the filter is **positional**:
a hypothetical `<image>-dbg-<machine>.rootfs.manifest` would pass and be
treated as a separate image.

---

## 5. Input format 2 — Yocto license manifest

**Location:** `licenses/<arch>/<image>-<machine>.rootfs-<timestamp>/license.manifest`
(the `<arch>` level was added in Yocto 4.3; both depths are searched).

**Written by** `write_license_files()` in `license_image.bbclass`. Blocks of
`KEY: value` lines separated by a blank line:

```
PACKAGE NAME: libcrypto
PACKAGE VERSION: 3.3.1
RECIPE NAME: openssl
LICENSE: Apache-2.0
```

This is the **preferred source**: the same inventory of installed packages as
the image manifest, plus licenses, plus the recipe name. It is not published
by the Yocto autobuilder, so many users will not have it.

### What the parser actually requires

Upstream always writes the four keys above in that order, but the parser does
not depend on it. The only enforced invariants are:

* every line contains a colon (split on the **first** colon, so values may
  contain colons);
* `PACKAGE NAME` is present and non-empty;
* no key appears twice within one block.

`PACKAGE VERSION`, `RECIPE NAME` and `LICENSE` are each optional and order is
irrelevant. A block with only a `PACKAGE NAME` parses to a component with no
version, no license and empty properties.

**Blocks are split on blank lines, not on the literal `"\n\n"`.** This
matters more than it looks: a block is accumulated into a dict, so if a
separator line held a stray space, two packages would merge and the first
would vanish from the SBOM with a zero exit code. Two blocks run together with
no separator at all are caught by the duplicate-key check. Both cases have
tests.

**`PACKAGE VERSION` goes through `normalize_version()`** (§7.1), the same
transform applied to the image manifest. This value is `PV`, which does not
carry an epoch or `PKGR` in practice — so on this path the transform can only
ever remove something legitimate. See §12.8.

### `image_license.manifest` is a different file and is not read

Same syntax, different keys, different order, different meaning:

```
RECIPE NAME: linux-yocto
VERSION: 6.10.14+git
LICENSE: GPL-2.0-only
FILES: bzImage--...-qemux86-64-20250610090225.bin modules--....tgz
```

It lists *deployed build artifacts* (kernel images, dtbs, module tarballs),
not installed packages. Note the trap: the version key is `VERSION`, not
`PACKAGE VERSION`, and there is no `PACKAGE NAME` at all — so a parser keying
on `PACKAGE NAME` reads zero records and reports success.

Discovery never picks the file up: the globs are `*/license.manifest` and
`*/*/license.manifest`, which do not match the name. The explicit rejection
inside `parse_license_manifest` is therefore **belt and braces**, reachable
only via a direct API call or a file *named* `license.manifest` that holds
image-license content. A directory containing only an `image_license.manifest`
fails at detection instead.

### The two manifests must not be joined by package name

The image manifest carries `debian.bbclass`-renamed names; the license
manifest carries the names from before that rename.

Checkable in this repository (from the 5.1-Styhead license manifest against
the image-manifest fixtures): `glibc`/`libc6`, `zlib`/`libz1`,
`libcrypto`/`libcrypto3`, `libkmod`/`libkmod2`, `liblzma`/`liblzma5`,
`util-linux-libblkid`/`libblkid1`. The same renaming affects `lzo`,
`ncurses-libtinfo` and the rest of the `util-linux-lib*` family upstream;
those pairs are illustrative, not measured here.

> **Provenance note.** The figure "13 of 57 packages disagree" comes from
> external research on a third-party build and **cannot be reproduced from
> these fixtures** — no build in `tests/fixtures/` carries both manifest
> kinds. Do not treat it, or the claim that the two files enumerate equal
> counts, as measured here.

There is a second obstacle: the license manifest writes `PV` (`2.43+git`)
while the image manifest writes `PKGV` (`2.43+git0+e9517114ac`), so versions
would not join either.

**The parser therefore reads one file or the other, never both.**

---

## 6. Input format 3 — Buildroot legal-info manifest

**Location:** `legal-info/manifest.csv`, written by `make legal-info`.

Standard CSV with a header row, read with `encoding="utf-8-sig"` (so an
editor-introduced BOM does not corrupt the `PACKAGE` header name) and
`newline=""`. Quoting is *inconsistent in the wild*: some builds quote every
field, others only fields containing a comma. CRLF line endings occur. Both
variants are in the fixtures.

```csv
"PACKAGE","VERSION","LICENSE","LICENSE FILES","SOURCE ARCHIVE","SOURCE SITE","DEPENDENCIES WITH LICENSES"
"glibc","2.36-81-g4f4d...","GPL-2.0+ (programs), LGPL-2.1+, BSD-3-Clause, MIT (library)",...
```

**Columns are located by header name, never by position.** `DEPENDENCIES WITH
LICENSES` was added in 2018.11, so a pre-2018.11 manifest has six columns and a
2023-era one has seven.

**`PACKAGE`, `VERSION` and `LICENSE` are all read and all required** — a
header missing any one is a hard error naming the missing column. Every other
column is ignored, which is what lets both shapes parse. A row is rejected
only when it is too short to reach those three; a row with fewer trailing
columns than the header is accepted.

**Rows are in build order, not sorted.** All-blank rows are skipped; an empty
`PACKAGE` cell is an error naming the line.

**`host-manifest.csv` is not read.** Nothing in the code ever names it; only
`manifest.csv` is looked for. (`find_manifest()` also accepts a file path
directly, so an API caller could point `parse()` at a host manifest — the CLI
cannot, since `detect()` refuses a non-directory.)

### Placeholder handling

Buildroot writes literal placeholders where it has no data:

| Column | Placeholder | Mapped to |
| --- | --- | --- |
| `VERSION` | `custom` (local tarball or git revision) | `version = None` |
| `LICENSE` | `unknown` (package declares none) | `license = None` |
| either | empty or whitespace-only | `None` |

Passing these through would put `pkg:generic/linux@custom` and a license named
`unknown` into the SBOM — presenting the absence of data as data.

The match is **exact and case-sensitive**, after stripping. `Custom`,
`UNKNOWN`, `n/a`, `none` and Buildroot's `not saved` are *not* recognised and
would pass into the purl. `not saved` appears only in `host-manifest.csv`,
which is not read.

---

## 7. Normalisation decisions and their rationale

Each of these is a place where the tool does *not* pass input through
verbatim. They are the decisions most worth challenging.

### 7.1 Yocto version: strip epoch and `-rN` revision

`normalize_version()` removes a leading `<digits>:` epoch and a trailing
`-r<digits>` revision. Applied on **both** Yocto paths.

**Why:** the same image built with `PACKAGE_CLASSES=package_rpm` and
`package_ipk` otherwise produces different SBOMs — `1.36.1` versus
`1.36.1-r0`. `PKGR` is Yocto's packaging revision and `PKGE` its epoch;
neither is part of the upstream version any CVE feed knows.

**Kept on purpose:** the `+git0+<sha>` suffix. That is part of `PKGV` and
identifies the actual source revision.

**Verified on real data, not only asserted.** `yocto-6.0.2-live` and
`yocto-6.0.2-ipk` are the same core-image-minimal from the same tree, packaged
with rpm and with ipk. Every ipk row carries a revision (36 `-r0`, two `-r1`)
and `netbase` carries the epoch `1:`; no rpm row carries either. All 37 purls
the two images share come out byte-identical. The one purl that differs,
`util-linux-flock`, is a genuine difference in image content -- the ipk image
installs 38 packages and the rpm image 37.

**Known risk:** an upstream version legitimately ending in `-r<digits>` would
be truncated. `PKGR` is always `r<N>` and the regex requires digits after the
`r` (so `1.2-rc1` is safe), but this is a heuristic. On the license-manifest
path the justification does not even apply — see §5.

### 7.2 Package architecture is not put in the purl

**Why:** rpm spells the tune arch `core2_64`, deb spells it `core2-64`, so
including it reintroduces exactly the backend dependence §7.1 removes. The
purl spec has also removed `arch` from the `yocto` type. And it adds nothing
to identity: a package name appears at most once per image.

The column is split off positionally so the version lands in the right field,
then **discarded unread** — it is not validated.

### 7.3 No qualifiers on Buildroot purls either

Buildroot supplies `SOURCE ARCHIVE` and `SOURCE SITE`, and `download_url` is a
spec-defined qualifier for the `generic` type. It is **not** emitted, for
consistency with §7.2: a mirror change would alter the purl of an otherwise
identical package, exactly the instability that argument rejects.

This is defensible in the other direction too. `LICENSE FILES` and
`DEPENDENCIES WITH LICENSES` are also read past — the latter carries real
inter-package edges (in the fixture, busybox depends on glibc and
linux-headers), which is the one place the tool has dependency data available
and discards it. See §12.5.

### 7.4 No CPE

An explicit decision, taken with the knowledge that it limits the tool.

Grype, Trivy and Dependency-Track do not resolve `pkg:generic` to a
vulnerability namespace — they reach the NVD through CPEs. So a scan of this
SBOM may report zero findings without that meaning "no vulnerabilities". The
project scope excludes CVE matching, and a generated CPE is a guess about
vendor and product strings; emitting one would look more authoritative than it
is. The README says so plainly rather than leaving it implied.

The `yocto:recipe` property is the partial mitigation: it carries the name a
CVE feed actually knows (`openssl` for the package `libcrypto`).

### 7.5 License strings are preserved, not coerced

Neither build system emits valid SPDX expressions. Yocto joins with `&` and
`|`; Buildroot uses commas and parenthetical scopes
(`GPL-2.0+ (programs), LGPL-2.1+`).

Strings go through `LicenseFactory.make_from_string()`:

| Input | CycloneDX output |
| --- | --- |
| `GPL-2.0-only` (valid SPDX id) | `{"license": {"id": "GPL-2.0-only"}}` |
| `MIT AND BSD-3-Clause` (valid expression) | `{"expression": "MIT AND BSD-3-Clause"}` |
| `GPL-2.0-only & bzip2-1.0.4` | `{"license": {"name": "GPL-2.0-only & bzip2-1.0.4"}}` |

Nothing is dropped and nothing is rewritten into an expression it does not
mean.

---

## 8. `detect()`

Returns a frozen `Detected(system: BuildSystem, root: Path)` — the build
system, and the directory the matching parser should be given.

**Probes**, tried in order, first match wins. Each build system is looked for
at the given path and at conventional levels below it, so pointing at
`./build` works as well as `./build/tmp/deploy`:

* Yocto: `.`, `tmp/deploy`, `build/tmp/deploy`
* Buildroot: `.`, `legal-info`, `output/legal-info`

**Evidence.** A directory is recognised by the *existence* of a path matching
`images/*/*.manifest`, `licenses/*/license.manifest`,
`licenses/*/*/license.manifest`, or by `manifest.csv` being a file.

This rules out the obvious false positive — an empty `images/` directory is
not a Yocto build — but it is an existence check, not a parse, and it does
**not** promise the parser will then succeed. Cases that detect and then fail
with exit 1:

* a deploy holding only a timestamped image manifest and no stable symlink
  (realistic: a tar or rsync that did not preserve symlinks);
* a deploy holding only a `-dbg` manifest;
* a zero-byte `manifest.csv`;
* several images and no `--image`.

**Ambiguity is an error, not a guess.** If a directory looks like both, it
raises — including when the two are found at different probe levels (a Yocto
deploy at `.` and a Buildroot manifest at `output/legal-info`). There is no
override flag; the recourse is to point deeper.

---

## 9. CycloneDX output

Spec version **1.6** by default — what Dependency-Track, Grype and Trivy read
today; 1.7 is newer than most consumers. It is a `to_json()` parameter, not a
constant, but the CLI exposes no flag for it.

### Mapping

| `Component` | CycloneDX |
| --- | --- |
| `name` | `component.name` |
| `version` | `component.version` — passed through verbatim |
| `purl` | `component.purl` **and** `component.bom-ref` |
| `license` | `component.licenses[0]`, via `make_from_string` (§7.5) |
| `supplier` | `component.supplier.name` (never set) |
| `hash` | `component.hashes[0]` (never set) |
| `properties` | `component.properties[]`, sorted by name |

Every component is `type: "library"`.

**Where the "no empty fields" guarantee lives.** The writer omits `licenses`,
`supplier`, `hashes` and `properties` when the field is falsy — but `version`
is passed straight through, and `to_json([Component(name="x", version="")])`
does emit `"version": ""`. Empty strings never reach the writer only because
the parsers convert them first (`normalize_version(...) or None`,
`_NO_VERSION`, `_NO_LICENSE`). The invariant is owned by the parsers, not by
`writer.py`.

**bom-ref collisions are resolved silently by the library.** `bom_ref` is set
to the purl string, but `bom.components` is a sorted set: two byte-identical
components collapse into one with no warning, and two components sharing a
purl but differing elsewhere both survive with one reassigned a generated
`BomRef.<n>` — and only that one keeps its root dependency edge. Both outcomes
are schema-valid, so validation will never catch it. No fixture triggers this
(all purls are unique), and nothing asserts it.

### Document structure

* `metadata.component` — the image, `type: "firmware"`, `bom-ref` = the
  product name. Firmware rather than application is the distinction a CRA
  reviewer cares about. `product_version` comes from `--product-version` and
  is **omitted entirely when not given** — no manifest records a product
  version, so a default would be invented data.
* `metadata.tools.components` — `sbom-embedded` and its version.
* `dependencies` — the array has **N+1 entries for N components**: one root
  entry whose `dependsOn` lists every package, plus a bare `{"ref": ...}` for
  each package. Only the root entry has a non-empty `dependsOn`.
  **This is not a real dependency graph.** The manifests read do not carry
  inter-package dependencies (Buildroot's do — see §7.3); the edges say "the
  image contains this". Without them, a consumer walking `dependencies` from
  the root sees nothing.

### Ordering and determinism

`bom.components` is a sorted set, so **output order is not parser order**. The
Buildroot fixture parses as `glibc, linux-headers, busybox, rpi-firmware,
linux` and renders as `busybox, glibc, linux, linux-headers, rpi-firmware`.
This is part of what makes output reproducible, alongside pinning the two
fields that would otherwise vary: `serial_number` and `timestamp` are
parameters of `build_bom()`/`to_json()`. The CLI passes neither, so real runs
get a fresh UUID and the current time; tests pin both.

---

## 10. CLI

```
sbom-embedded PATH [--format cyclonedx] [--image NAME] [--name NAME]
                   [--product-version VERSION] [-o FILE] [--version]
```

* The SBOM goes to **stdout** via `sys.stdout.write`, with a trailing newline,
  so `> sbom.json` produces a well-formed text file. With `-o`, stdout stays
  empty and a progress line goes to stderr.
* **Two different error contracts:**
  * Detection and parse errors are caught, printed to stderr as
    `error: <message>`, and exit **1**. No traceback. Output-file write
    failures are handled the same way.
  * Usage errors — `--image` on a Buildroot directory, `--format` with
    anything but `cyclonedx` — are raised as `typer.BadParameter` and come out
    as click's boxed usage error with exit **2**.
* **An empty package list is warned about on stderr** and still written. A
  valid but empty SBOM is the worst possible compliance artifact: it reads as
  a clean result.
* `--name` sets both `metadata.component.name` and its `bom-ref`. It defaults
  to the manifest **label** (`core-image-minimal-qemux86-64`) — or, for
  Buildroot, the literal string `buildroot`, since a legal-info manifest
  carries no product identity of its own.
* `--product-version` sets `metadata.component.version`. Without it the field
  is absent from the document — not `0.0.0`, not `unknown`, not a date. No
  manifest this tool reads carries a product version.
* `--version` prints `sbom-embedded 0.1.0` to stdout and exits 0. It is eager,
  so it wins even with an invalid PATH. (Not to be confused with
  `--product-version`.)
* The `wrote N components` line counts the parsed list, not the rendered
  document — if the writer deduplicated anything, it would over-count.

### Image selection

A Yocto deploy directory with several images stops rather than choosing:

```
error: ./build/tmp/deploy holds several images (core-image-full-cmdline,
core-image-minimal); pick one with --image
```

The listed values are short image names where those are unambiguous, and full
labels otherwise — so every value printed selects exactly one manifest.

`--image` matches by **exact equality** against either the label
(`core-image-minimal-qemux86-64`) or the short image name
(`core-image-minimal`) — never by prefix, so `core-image-minimal` does not
match `core-image-minimal-dev`. An exact label match wins over a short-name
match, which is what makes a license directory named `core-image-minimal`
selectable when an image manifest for `core-image-minimal-qemux86-64` sits
beside it.

The short name can only be derived for a license manifest when an image
manifest in the same tree revealed the machine name. Where only license
manifests exist, `--image` takes the full label.

---

## 11. Testing

92 tests, ~1.5 s. Run: `.venv/bin/python -m pytest`.

**Fixtures are unmodified output from real builds** — 12 manifest files across
7 fixture directories, laid out as the directory a user would point the CLI
at. No generated or hand-written manifest is used as a positive fixture,
because the format details are exactly what a parser gets wrong from memory.
`tests/fixtures/PROVENANCE.md` records the source URL, licence and purpose of
each.

| Fixture | Source | What it covers |
| --- | --- | --- |
| `yocto-5.0.9` | Yocto autobuilder | LTS release; `core2_64` arch spelling |
| `yocto-6.0.2` | Yocto autobuilder | Two images (ambiguity); 444 packages; `x86_64_v3` arch |
| `yocto-5.1-styhead` | blackducksoftware/bd_scan_yocto_via_sbom (MIT) | License manifest; `image_license.manifest` shape; recipe fan-out |
| `buildroot-2023.02` | CycloneDX/cyclonedx-buildroot (Apache-2.0) | Fully quoted CSV; empty `LICENSE FILES` cells |
| `buildroot-minimal-quoting` | CycloneDX/cyclonedx-buildroot (Apache-2.0) | Minimal quoting; CRLF; `unknown` license |
| `yocto-6.0.2-live` | built on the development machine | A whole deploy tree from one build: both manifest kinds, real directory names, and the symlink/timestamp duplicate |
| `buildroot-2026.08` | built on the development machine | Current release; 44 packages; a 296-character license with nested parentheses; `1.9.17p2` / `10.5p1` / `6.6-20251231` version forms |
| `yocto-6.0.2-ipk` | built on the development machine | The **ipk** backend: every row carries `-r0` or `-r1`, one carries the epoch `1:`, the arch column is hyphenated `x86-64-v3`. Paired with `yocto-6.0.2-live` it is what proves §7.1 on real data |

Fixtures were chosen for permissive licensing as well as coverage; GPL-3.0
candidates with unique test value were rejected on those grounds.

Cases no real fixture contains are constructed in `tmp_path`: empty arch
column, trailing empty version, four-field line, zero-byte manifest,
six-column Buildroot header, short rows, timestamped and `-dbg` image
manifests, whitespace-only and missing block separators, a `host-manifest.csv`
beside the target one, and an unwritable output path.

### What has been exercised on a live build

Buildroot: fully. A real `make legal-info` and a real `make` were both run on
Buildroot 2026.08-rc3 on the development machine. The manifest from the former
is the `buildroot-2026.08` fixture; the latter produced an 867,355-file output
tree used to confirm that `detect()` is not fooled by the `*.manifest` files
that appear inside host package sources.

Yocto: also fully. `bitbake core-image-minimal` was run to completion for
qemux86-64 on the Yocto 6.0.2 release revisions, and the tool was run against
the `tmp/deploy` directory it wrote: 39 components, all with a purl, a license
and a recipe property, schema-valid, 0.09 s. That deploy tree is the
`yocto-6.0.2-live` fixture.

Getting there took two failed attempts, both stopped by measurement rather
than guesswork, and both worth recording because they constrain which
Yocto/host combinations work at all:

* poky `scarthgap` branch tip parses and runs, but the public sstate mirror
  returned a 0% match -- 2012 setscene tasks wanted, 2012 missed -- putting the
  build back at its from-source footprint of 22-40 GB, against 7 GB of free
  disk.
* the `yocto-5.0.9` release tag, where the mirror does hold artifacts, fails
  for two independent reasons on a current host: its bitbake crashes on Python
  3.14 (`_pickle.PicklingError` in the async server), and its
  `UNINATIVE_MAXGLIBCVERSION = "2.41"` is below the host's glibc 2.43.

What worked was building the 6.0.2 release revisions from the release tarballs
with the public sstate mirror configured: 373 of 396 wanted objects came from
the mirror (94% match), which is what made it fit.

**Schema validation** is real but not universal: every writer test that
renders a document goes through a helper that runs `JsonStrictValidator`
against CycloneDX 1.6. The determinism test compares two `to_json` strings
without validating them.

**Referential integrity is asserted.** Tests check that every component's
`bom-ref` equals its `purl`, that every `ref` and `dependsOn` entry in
`dependencies` resolves to a known `bom-ref`, and that the root owns exactly
the component set — on synthetic components and again end-to-end on every
fixture.

---

## 12. Known limitations

1. **A `pkg:generic` purl does not match CVEs on its own** (§7.4).
2. **No licenses from a Yocto image manifest** — the format has none.
3. **Image-manifest package names are the Debian-renamed forms** (`libc6`,
   `libz1`), with no recipe information available to map them back.
4. **`supplier` and `hash` are never populated.**
5. **`dependencies` is a flat root-to-package list**, not a real graph — even
   for Buildroot, where the input carries real edges (§7.3).
6. **Buildroot `SOURCE ARCHIVE`, `SOURCE SITE`, `LICENSE FILES` and
   `DEPENDENCIES WITH LICENSES` are read past, not emitted.**
7. **The Buildroot root component is named `buildroot`** unless `--name` is
   passed. For a CRA artifact, the product identity is a placeholder by
   default. The product version is absent unless `--product-version` is
   given — deliberately, since no manifest records one.
8. **The `-rN` strip is a heuristic**, and is applied to the license-manifest
   path where its justification does not hold (§5, §7.1).
9. **`--image` selection by short name needs an image manifest present**
   (§10).

---

## 13. Where a reviewer should look hardest

Ranked by where a defect would be most damaging and least visible.

1. **`normalize_version()`** — the only lossy transformation applied to
   version strings, and it runs on both Yocto paths. `1.2-rc1`,
   `2.39+git0+662516aca8` and `2:1.36.1-r12` are covered by tests; what is
   not?
2. **`parse_license_manifest()` block splitting** — a dict per block means any
   failure to separate two records drops a package with exit 0. The
   blank-line split and the duplicate-key guard are the two defences; both
   have tests. Is there a third way to merge blocks?
3. **`parse_image_manifest()`'s three-field split** — the empty-column
   handling is driven by an `opkg_query` code path no fixture exercises. One
   synthetic test (`test_an_empty_column_is_not_mistaken_for_a_malformed_line`)
   covers both empty-arch and empty-version in two lines.
4. **Manifest discovery uses two different mechanisms.** Image manifests are
   filtered by whether the stem ends in `-<machine>` (no dedup dict at all);
   license manifests are deduplicated by label collision. If either were
   wrong, packages would be silently doubled or dropped. Both now have
   negative-case tests; check they hold for layouts other than the fixtures'.
5. **`bom-ref` uniqueness** — §9 describes what the library does on a
   collision. The mapping and referential integrity are now asserted, but
   nothing constructs a collision, so that path is still unexercised.
6. **`detect()` probe order** — first match wins, and `.` is tried first.
   Consider a build tree where a parent directory coincidentally matches.
7. **Placeholder sets in `buildroot.py`** — `_NO_VERSION = {"", "custom"}` and
   `_NO_LICENSE = {"", "unknown"}` are exact, case-sensitive, closed sets. Are
   there other placeholders in a target manifest?
8. **The `properties` escape hatch** — is a generic `dict[str, str]` the right
   shape, or should `recipe` be a first-class field?
9. **The `else` arm in `cli.py`** — a `BuildSystem` member added without a
   parser now raises rather than falling through to Buildroot. Confirm no
   other dispatch has the same shape.

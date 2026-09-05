# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-05

Ten defects, found by auditing the codebase against its own documented
promises. Four of them produced a wrong SBOM with exit code 0, which the
README calls the worst possible outcome for a compliance artifact.

The version is a minor rather than a patch because several of these change
behaviour a user could notice: inputs that used to produce a document now
exit 1, and Yocto purls change on builds that use a PR service.

### Fixed

- **A rebuilt deploy directory reported the oldest build.** `licenses/`
  accumulates one `<image>-<machine>.rootfs-<DATETIME>/` per build and bitbake
  removes none of them. Discovery kept whichever path sorted first, and since
  `%Y%m%d%H%M%S` sorts chronologically, that was deterministically the
  *earliest* build — a complete, plausible, schema-valid package list for
  firmware no longer on disk, at exit 0. Packages added since were missing
  entirely and moved versions were reported at the old value, so a scan would
  clear vulnerabilities that are actually shipped. Directories are now ranked:
  the symlink wins, then the newest timestamp. Also fixes a pre-4.3 layout
  left beside a current one, and a renamed `SSTATE_PKGARCH` directory.
- **Yocto package revisions from a PR service were not stripped.**
  `PKGR = "${PR}${EXTENDPRAUTO}"`, and `EXTENDPRAUTO` is `.${PRAUTO}` whenever
  `PRSERV_HOST` is set, so `r0` becomes `r0.1`. The regex matched only
  `-r<digits>`, so an ipk or deb build with a PR service produced different
  purls from the rpm build of the same image — the exact backend dependence
  this normalisation exists to prevent. The `INC_PR` idiom produces the same
  shape with no PR service at all, and a chained upstream PR server produces
  `r0.3.0`. `DESIGN.md` §7.1 asserted "PKGR is always r<N>"; it is not.
- **An unreadable directory looked like an empty one.** `Path.glob` reports a
  directory it may not read as no matches, so an unreadable `licenses/<arch>/`
  made the tool fall back to the image manifest and emit a complete-looking
  SBOM with no licenses and no recipe names, at exit 0. It now raises and names
  the directory, and `detect()` no longer reports "neither a Yocto nor a
  Buildroot directory" for evidence it simply was not allowed to read.
- **A duplicate purl produced non-reproducible output and lost a component.**
  `bom-ref` is the purl, and CycloneDX requires bom-refs to be unique — a rule
  the JSON schema does not enforce. Left to the library, the second of two
  components sharing a purl was reassigned a generated `BomRef.<random>` that
  changed on every run and received no entry in `dependencies` at all. Repeats
  that agree are now collapsed with a warning; repeats that contradict each
  other exit 1. The root component's ref is checked against the same
  namespace, since `--name` controls it.
- **A byte order mark corrupted the first package.** Yocto manifests were read
  as `utf-8` while the Buildroot CSV was already read as `utf-8-sig` for
  exactly this reason. U+FEFF is category `Cf`, not whitespace, so `strip()`
  kept it: the first package was emitted with a name and purl nothing can
  resolve, at exit 0. On the license path the same BOM hid the `PACKAGE NAME`
  key and produced a confidently wrong diagnosis.
- **A package name of only slashes crashed with a traceback.** packageurl
  normalises such a name to nothing and then raises `TypeError`, which
  `cli.py` does not catch — 5 KB of rich traceback quoting absolute paths,
  which `SECURITY.md` names explicitly as in scope. All three parsers reached
  it; the emptiness guards did not, because `"/"` is not blank.
- **The stdout write had no error handling**, though the `-o` path did and the
  README leads with `> sbom.json`. A closed descriptor produced a traceback; a
  failing write surfaced only at interpreter shutdown, as exit 120 with
  `Exception ignored while flushing sys.stdout` and a truncated file. Both are
  now `error: <message>` and exit 1.
- **A broken pipe exited 1 with an empty stderr**, colliding with the code
  reserved for `error: <message>`, and only once the document outgrew the pipe
  buffer — so `sbom-embedded ... | head` looked nondeterministic. It now exits
  141, as a shell utility does.
- **`bom-ref` and `purl` could disagree.** They were serialised from two
  representations of the same value, and `PackageURL.from_string` re-normalises
  path segments, so the emitted purl was not always the one the tool computed.
- **`-o` truncated its destination before writing.** A failure part-way
  through -- a full disk, a quota, a broken mount -- left a truncated file
  where a previously good SBOM had been, and that file is not valid JSON. The
  exit code said the run failed; the artifact beside it said otherwise, and in
  a pipeline that overwrites a kept `sbom.json` the previous one was simply
  gone. The document is now written to a temporary file in the same directory,
  fsynced, given the mode a plain write would have produced, and renamed over
  the destination.
- **A path to `manifest.csv` was refused**, though `buildroot.find_manifest`
  has documented accepting it from the start -- "the file itself, because all
  three are things a person reasonably types". Nothing reached that branch,
  because `detect()` rejected every non-directory first. Only that exact name
  is taken: `host-manifest.csv` has the same columns and the same parser but
  lists the build host's tools, so accepting any file by path would have put
  ccache and pkgconf into a firmware SBOM.
- **Two error paths echoed unbounded input.** `_excerpt()` bounds every other
  message in `yocto.py`; the missing-`PACKAGE NAME` and duplicate-key paths
  interpolated raw keys at full length, so a 5 MB line produced 5 MB of stderr.
- **One image losing its licenses was masked by another.** The
  unreadable-directory check above was gated on "no license manifest anywhere",
  but a deploy normally holds several images -- that is what `--image` is for.
  One image's readable licence directory therefore hid another's blocked one,
  and the SBOM for the image actually requested came out at exit 0 with every
  licence and recipe name missing. The check now lives where the fallback is
  decided, fires per image, and ignores a blocked directory whose label was
  already read, so a stale unreadable rebuild directory does not fail a good
  deploy.
- **Two of the three unreadable-directory probes were a level too shallow.**
  `detect()` walked three levels, which cannot reach
  `licenses/<arch>/<image>/` -- the standard layout since Yocto 4.3 -- so a
  permission problem there was still reported as "not a build directory at
  all". `parse()` walked one level under `images/`, which can only ever list
  `images/` itself and never `images/<machine>/`.
- **Two license directories could still tie.** Ranking on the timestamp in the
  directory name leaves two untimestamped directories equal, so an
  `SSTATE_PKGARCH` rename that left a symlink in each arch directory was
  resolved by alphabetical order -- picking the older arch name. The rank now
  reads the timestamp through the symlink's target, and falls back to
  modification time when a copy has flattened the symlinks away.
- **The missing-`PACKAGE NAME` error was still proportional to the input.**
  Excerpting each key bounded one enormous key but not a large number of small
  ones: a 926 KB block produced 417 KB of stderr. The list is now capped at
  eight keys plus a count, and the same input produces 1.4 KB.
- **`writer.py` claimed 4000 packages rendered in 1.6 s.** They take about 54
  seconds. `output_as_string()` calls `Bom.validate()`, which calls
  `register_dependency()` once per component, each doing a linear scan of the
  dependency set — so the quadratic pass this code avoids when building the
  edges happens anyway, inside the library, and dominates. The cost is upstream
  and cannot be skipped through the public API; it is now measured and stated
  in `README.md` and `DESIGN.md` §12 instead of contradicted.

### Changed

- `cyclonedx-python-lib` is now capped at `<12`. The documented entry points
  are `pipx run` and `uvx`, which resolve at run time, so an uncapped
  dependency means users meet a breaking release before CI does. That library
  ships a major roughly every four to five months, v8 moved the
  `metadata.tools` chain this code calls, and `contrib` — which `writer.py`
  imports — is documented upstream as not following the core's versioning
  rules. `typer` and `packageurl-python` are deliberately left uncapped.
- CI gained a weekly schedule and an `upstream-canary` job that installs the
  newest dependencies (and a `--pre` variant) past the declared cap, runs the
  suite with `-W error::DeprecationWarning`, and exercises the CLI. Without it
  the cap would just be a slow way to go stale.
- The `wrote N components` line now counts what the document holds rather than
  the parsed list.
- The publish workflow now runs the test suite before building. It is
  triggered by a tag rather than by the CI run that tested the commit, so a tag
  pushed to a red `main` would otherwise publish a broken release — and a PyPI
  release cannot be replaced, only yanked.
- A test ties `__version__` to the packaged distribution version. It feeds both
  `--version` and every SBOM's `metadata.tools` entry, so a forgotten bump
  would misattribute every document a release produces.
- Two tests that asserted the duplicate handling were removed: both passed
  against the pre-fix writer, because the library already collapses two
  byte-identical components on its own, so neither could ever have caught the
  defect it was named for. The case that actually broke -- two names that are
  distinct strings but indistinguishable as purls -- is now the test.
- The closed-stdout test quoted its arguments; it would have failed on any
  checkout path containing a space, for reasons unrelated to what it tests.
- `CONTRIBUTING.md` now describes the two jobs that do not run on a pull
  request, and why neither should gate a merge.

### Documentation

- `DESIGN.md` §5 carried a note saying no fixture holds both manifest kinds
  and that the disagreement could not be measured here. Both halves were false:
  `yocto-6.0.2-live` holds both, and a test pins the numbers.
- `DESIGN.md` §11 said 12 manifest files across 7 fixture directories; there
  are 13 across 8. The stated suite runtime was roughly twenty times under.
- `PROVENANCE.md` said all 38 ipk rows carry `-r0`; 36 do and two carry `-r1`,
  contradicting `DESIGN.md` §7.1 and the README. It also described a committed
  fixture file as a symlink; git stores both copies as ordinary files.
- The README's "dependency graph is flat" note said no manifest read carries
  inter-package dependencies. Buildroot's `DEPENDENCIES WITH LICENSES` column
  does, as `DESIGN.md` §7.3 already said.
- `SECURITY.md` and `DESIGN.md` named a hard-coded version that had already
  gone stale.

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

[Unreleased]: https://github.com/RchrdWrd/sbom-embedded/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/RchrdWrd/sbom-embedded/releases/tag/v0.2.0
[0.1.1]: https://github.com/RchrdWrd/sbom-embedded/releases/tag/v0.1.1
[0.1.0]: https://github.com/RchrdWrd/sbom-embedded/releases/tag/v0.1.0

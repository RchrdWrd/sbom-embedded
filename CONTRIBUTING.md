# Contributing

## Setup

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

Before opening a pull request:

```bash
.venv/bin/ruff check src tests
.venv/bin/ruff format --check src tests
.venv/bin/mypy
.venv/bin/python -m pytest
```

CI runs all four on Python 3.11 through 3.14, builds the distribution, and
installs the declared dependency floors to check they are real.

Two jobs do not run on a pull request, and are worth knowing about:

* **`upstream-canary`** runs weekly, and on demand from the Actions tab. It
  installs the newest dependencies *past* the cap `pyproject.toml` declares,
  and a `--pre` variant so a new major shows up before its final release, then
  runs the suite with `-W error::DeprecationWarning`. It is what keeps the cap
  from silently going stale, and it must never gate a merge, because it fails
  for reasons that have nothing to do with the change under review.
* The **Publish** workflow runs the suite before it builds. It is triggered by
  a tag rather than by the CI run that tested the commit, so without that a tag
  pushed to a red `main` would publish a broken release.

## Fixtures

Every fixture under `tests/fixtures` is unmodified output from a real Yocto or
Buildroot build. **Do not add a hand-written or generated manifest as a
positive fixture.** The format details are exactly what a parser gets wrong
from memory, and a fixture invented to match the parser proves nothing.

Degenerate cases that no real build produces — an empty column, a zero-byte
manifest, a malformed line — are constructed inside the test that needs them,
in `tmp_path`, where it is obvious they are synthetic.

If you add a fixture, record in
[`tests/fixtures/PROVENANCE.md`](tests/fixtures/PROVENANCE.md) where it came
from, under what licence, and what it covers that no other fixture does.

## Design decisions

[`DESIGN.md`](DESIGN.md) explains the manifest formats and the reasoning
behind each non-obvious choice — in particular why versions are normalised,
why the purl carries no qualifiers, and why no CPE is emitted. If a change
contradicts something written there, update the document in the same commit.

The rule that governs the rest: **nothing is filled in that the manifests do
not record.** A missing field is honest; an invented one is a lie in a
compliance artifact.

## Releasing

Publishing runs from `.github/workflows/publish.yml` through PyPI Trusted
Publishing, so there is no API token in the repository or in GitHub secrets —
PyPI verifies the workflow's identity over OpenID Connect.

### One-time setup

On PyPI, under *Your account → Publishing → Add a pending publisher*
(the account sidebar, not a project's — the project may not exist yet):

| Field | Value |
| --- | --- |
| PyPI project name | `sbom-embedded` |
| Owner | `RchrdWrd` |
| Repository name | `sbom-embedded` |
| Workflow name | `publish.yml` |
| Environment name | `pypi` |

Repeat on [test.pypi.org](https://test.pypi.org) with environment `testpypi`.
TestPyPI has a separate account database, so it needs its own registration.

Then, under *Settings → Environments*, add a **required reviewer** to the
`pypi` environment. Without it a tag push publishes immediately, with no
confirmation, and a PyPI release cannot be replaced — only yanked.

### To release

1. Run the **Publish** workflow manually against `testpypi` and look at the
   rendered project page. A release's README cannot be edited afterwards.
2. Bump `version` in `pyproject.toml` and `__version__` in
   `src/sbom_embedded/__init__.py`; update `CHANGELOG.md`; commit.
3. `git tag -a v0.2.0 -m "..." && git push origin v0.2.0`

The tag push triggers the release. The workflow refuses to publish if the tag
and the packaged version disagree, and it installs the built wheel and
generates an SBOM with it before either upload step runs.

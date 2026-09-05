"""The one component model every parser returns.

Parsers know about manifest formats; the CycloneDX writer knows about
CycloneDX. `Component` is the only thing they share, which is why adding a
build system means adding a parser and nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from packageurl import PackageURL

# Neither Yocto nor Buildroot has a registered purl type, and their packages
# are not published to any ecosystem repository. "generic" with a name and
# version is what CVE matchers (Grype, Trivy, OSV) can actually consume, and a
# component without a purl is invisible to all of them -- so every Component
# gets one, derived if the parser did not supply a better-qualified string.
PURL_TYPE = "generic"


def make_purl(
    name: str,
    version: str | None = None,
    *,
    qualifiers: dict[str, str | None] | None = None,
) -> str:
    """Build a purl string, dropping qualifiers the manifest did not fill in.

    Raises `ValueError` for a name that has no purl form at all. packageurl
    signals that inconsistently -- a `ValueError` for the empty string, but a
    bare `TypeError` from inside `"".join(...)` for a name that its own
    normalisation reduces to nothing -- and a `TypeError` escaping a parser
    reaches the user as a traceback rather than the documented `error:` line.
    """
    kept = {k: v for k, v in (qualifiers or {}).items() if v}
    try:
        built = PackageURL(
            type=PURL_TYPE,
            name=name,
            version=version or None,
            qualifiers=kept or None,
        ).to_string()
        # Parse it back and re-emit. `to_string()` is not a fixed point for
        # every name -- packageurl percent-encodes whitespace on the way out
        # and drops it again on the way in, so `a /b` and `a/b` build different
        # strings that read back as one. The writer emits a purl by parsing
        # this string, so settling the canonical form here is what keeps
        # `Component.purl` equal to what the document will carry, and keeps two
        # names that are indistinguishable as purls from reaching the writer as
        # two identities.
        return PackageURL.from_string(built).to_string()
    except (TypeError, ValueError) as err:
        raise ValueError(f"{name!r} has no purl form: {err}") from err


def has_purl_form(name: str) -> bool:
    """Whether `name` can be carried in a purl at all.

    packageurl splits a name on `/` and normalises each segment, so a name made
    only of slashes -- `/`, `//`, `///` -- reduces to nothing and cannot be
    represented, even though it is not blank and `str.strip()` leaves it alone.
    Asking the library rather than reimplementing its rules is deliberate: the
    answer cannot then drift from what `make_purl` will actually do.
    """
    try:
        make_purl(name)
    except ValueError:
        return False
    return True


@dataclass(slots=True)
class Component:
    """One package installed in the image.

    Only `name` is guaranteed by every manifest format we read. A Yocto image
    manifest, for instance, carries no license and no supplier at all -- those
    stay None rather than being invented.
    """

    name: str
    version: str | None = None
    supplier: str | None = None
    license: str | None = None
    hash: str | None = None
    purl: str | None = None
    # Build-system-specific provenance that has no field of its own, keyed by
    # a namespaced name. A Yocto package records the recipe that produced it:
    # "libcrypto" and "openssl-conf" both come from openssl, and openssl is
    # the name a CVE feed knows. Emitted as CycloneDX properties.
    properties: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("component name must not be empty")
        if self.purl is None:
            self.purl = make_purl(self.name, self.version)

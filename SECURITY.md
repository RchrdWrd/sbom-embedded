# Security policy

## Supported versions

Only the latest release is supported. Fixes go onto `main` and ship in the
next release; there are no maintained release branches.

## Reporting a vulnerability

Please report privately through GitHub's
[security advisory form](https://github.com/RchrdWrd/sbom-embedded/security/advisories/new)
rather than opening a public issue.

## Threat model

This tool reads manifest files and writes a JSON document. It starts no build,
runs no subprocess, opens no network connection, and executes nothing it
reads.

The input is nonetheless worth thinking about: a manifest comes from a build
system, and a build system consumes third-party sources. Treat a manifest as
untrusted text. Reports of a malformed manifest causing anything worse than a
non-zero exit -- unbounded memory use, a hang, a write outside the output
path, a traceback carrying environment details -- are in scope.

## Not a vulnerability

**A clean vulnerability scan of an SBOM this tool produced is not evidence
that the firmware is clean.** Components carry `pkg:generic` purls, which
Grype, Trivy and Dependency-Track do not resolve to a vulnerability namespace.
This is a documented limitation of the identifier, explained in the README,
not a defect in this tool.

**Nor is a scan that reports a package your build has already patched.** Yocto
and Buildroot fix packages without changing the recorded version, and the
manifests read here do not record the patches — so a version this SBOM reports
as vulnerable may not be. That is a limitation of the input, explained in the
README, and not something this tool can resolve from what it is given.

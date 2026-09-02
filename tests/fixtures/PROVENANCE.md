# Fixture provenance

Every fixture here is unmodified output from a real build. Manifest formats
differ between releases in ways that are easy to get wrong from memory, so
nothing in this directory is hand-written.

## yocto-6.0.2, yocto-5.0.9

Image manifests published by the Yocto Project autobuilder, downloaded from:

    https://downloads.yoctoproject.org/releases/yocto/yocto-6.0.2/machines/qemu/qemux86-64/
    https://downloads.yoctoproject.org/releases/yocto/yocto-5.0.9/machines/qemu/qemux86-64/

Each fixture directory is laid out as the `tmp/deploy` directory a user
points the CLI at, so `images/<machine>/<image>.rootfs.manifest` sits where
a real build would put it.

Two releases are kept on purpose: 5.0 is the current LTS and 6.0 is current,
and the package architecture column changed between them
(`core2_64` -> `x86_64_v3`).

Licence: these are build artifacts published by the Yocto Project, which
distributes its metadata under MIT. They are lists of package names and
version numbers -- facts about a build rather than creative work.

Not published by the autobuilder, and therefore not available here:
`licenses/<image>/license.manifest`, which is the only Yocto artifact that
carries per-package license text.

## buildroot-2023.02, buildroot-minimal-quoting

Real `make legal-info` output committed to the CycloneDX project's own
Buildroot tooling repository (Apache-2.0), downloaded from:

    https://raw.githubusercontent.com/CycloneDX/cyclonedx-buildroot/main/tests/_data/raspi_manifest.csv
    https://raw.githubusercontent.com/CycloneDX/cyclonedx-buildroot/main/tests/_data/manifest.csv

Each is placed under `legal-info/` so the fixture directory looks like the
`output/` directory a user points the CLI at.

`buildroot-2023.02` is a Raspberry Pi build on Buildroot 2023.02: every field
is quoted, and it contains both the `custom` version placeholder and empty
`LICENSE FILES` values.

`buildroot-minimal-quoting` is a Laird/Summit vendor fork. It is kept for the
two things it does differently: fields are bare unless they contain a comma,
and the file has CRLF line endings. A parser that only ever saw the
all-quoted LF form would pass its tests and fail on this.

Buildroot publishes no build output of its own, so unlike the Yocto fixtures
these could not be taken from an upstream release.

## yocto-5.1-styhead

Real `license.manifest` and `image_license.manifest` from a Yocto 5.1
(Styhead) `core-image-minimal` build for qemux86-64, committed as test data
in Black Duck's Yocto scanning tool (MIT), downloaded from:

    https://raw.githubusercontent.com/blackducksoftware/bd_scan_yocto_via_sbom/main/test/data/license.manifest
    https://raw.githubusercontent.com/blackducksoftware/bd_scan_yocto_via_sbom/main/test/data/image_license.manifest

The Yocto autobuilder does not publish license manifests, so unlike the image
manifests these had to come from a third party.

**File contents are byte-for-byte the originals. The enclosing directory path
is reconstructed**, because the source repository stores both files flat. What
the path encodes was taken from the files themselves and their siblings, not
invented:

* `qemux86-64` and the `20250610090225` timestamp are read out of the build
  artifact name inside `image_license.manifest`
  (`bzImage--6.10.14+git0+83eed9befe_bbe3d1be4e-r0-qemux86-64-20250610090225.bin`).
* `core-image-minimal` is the image named in the sibling `pn-buildlist`.
* `qemux86_64` as the arch level, and the `.rootfs-<timestamp>` suffix, follow
  the layout `license_image.bbclass` writes for Yocto 4.3 and newer.

This pair is kept for two things no other fixture provides: licenses for Yocto
components at all, and the two *different* block formats -- `license.manifest`
uses `PACKAGE NAME` / `PACKAGE VERSION` / `RECIPE NAME` / `LICENSE`, while
`image_license.manifest` uses `RECIPE NAME` / `VERSION` / `LICENSE` / `FILES`.
A parser that keys on `PACKAGE NAME` silently reads zero records from the
second one.

## buildroot-2026.08

Output of a build run on the development machine itself, not obtained from a
third party:

    git clone https://gitlab.com/buildroot.org/buildroot.git
    make qemu_x86_64_defconfig
    # plus 44 BR2_PACKAGE_* symbols enabled to get a realistic package count
    make legal-info

Buildroot `2026.08-rc3-28-g79fd6241e4` (commit
`79fd6241e4347f67d659cc02669448397b458d52`), 44 target packages.

Kept because it is the current release and because of one thing no other
fixture has: a 296-character `LICENSE` value with nested parentheses and
commas --

    GPL-2.0+ (programs), LGPL-2.1+, BSD-2-Clause, BSD-3-Clause, BSL-1.0,
    FSFAP, ISC, other permissive licenses, public domain (library), LGPL-3.0+
    (sysdeps/htl/raise.c, for Hurd only), GPL-3.0+ (scripts/move-if-change),
    GPL-3.0+ WITH Texinfo-exception (manual/texinfo.tex), GFDL-1.3-or-later
    (manual)

-- which is what a real glibc row looks like today. It also carries version
forms the other fixtures do not: `1.9.17p2`, `10.5p1`, `6.6-20251231`, and a
git-describe version (`2.44-36-g2d5421ffca...`).

Licence: Buildroot is GPL-2.0+, but this file is generated output listing
package names, versions and licence identifiers -- facts about a build.

## yocto-6.0.2-live

A `tmp/deploy` directory from a bitbake run performed on the development
machine. Unlike every other Yocto fixture here, the directory names are the
ones bitbake wrote -- nothing is reconstructed.

    # openembedded-core 5d1aa5c8, bitbake acfe02fa, meta-yocto 24c24cef
    # (the yocto-6.0.2 release revisions, from the release tarballs)
    DISTRO=poky MACHINE=qemux86-64
    SSTATE_MIRRORS = "file://.* http://sstate.yoctoproject.org/all/PATH;downloadfilename=PATH"
    bitbake core-image-minimal

The public sstate mirror supplied 373 of 396 wanted objects (94% match), which
is what made the build fit on a machine with 7 GB of free disk.

Four files are kept, and each earns its place:

* `images/qemux86-64/core-image-minimal-qemux86-64.rootfs.manifest` and the
  `-20260902171159` copy it is a symlink to. Both are committed on purpose:
  this is the real form of the duplicate a naive glob would count twice.
* `licenses/qemux86_64/core-image-minimal-qemux86-64.rootfs-20260902171159/license.manifest`
  -- 39 packages with licenses and recipe names.
* the `image_license.manifest` beside it, which uses the other key set.

**This is the only fixture holding both manifest kinds from one build**, which
makes it the only one that can demonstrate why they must not be joined by
package name. Measured here: the image manifest lists 37 packages, the license
manifest 39, and 11 of the 37 names have no counterpart -- `libc6`/`glibc`,
`libz1`/`zlib`, `libcrypto3`/`libcrypto`, `libkmod2`/`libkmod`,
`liblzma5`/`liblzma`, the `libacl1`/`libattr1`/`libblkid1` family, and the
three versioned `kernel-*-6.18.24-yocto-standard` packages. The two extra
entries on the license side, `run-postinsts` and `util-linux-flock`, are
packages that do not survive into the final rootfs.

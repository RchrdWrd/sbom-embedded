import re

import pytest

from sbom_embedded.parsers.yocto import (
    YoctoParseError,
    find_image_manifests,
    parse,
    parse_image_manifest,
    parse_license_manifest,
)


def test_finds_the_image_from_the_layout(fixtures):
    manifests = find_image_manifests(fixtures / "yocto-5.0.9")
    assert [(m.image, m.label) for m in manifests] == [
        ("core-image-minimal", "core-image-minimal-qemux86-64")
    ]


def test_several_images_are_ambiguous_rather_than_guessed(fixtures):
    with pytest.raises(YoctoParseError) as exc:
        parse(fixtures / "yocto-6.0.2")
    message = str(exc.value)
    assert "core-image-minimal" in message
    assert "core-image-full-cmdline" in message
    assert "--image" in message


def test_an_image_can_be_selected_by_name(fixtures):
    components, label = parse(fixtures / "yocto-6.0.2", image="core-image-minimal")
    assert label == "core-image-minimal-qemux86-64"
    assert len(components) == 38


def test_the_purl_is_plain_name_and_version(fixtures):
    components, _ = parse(fixtures / "yocto-5.0.9")
    busybox = next(c for c in components if c.name == "busybox")
    assert busybox.version == "1.36.1"
    assert busybox.purl == "pkg:generic/busybox@1.36.1"


def test_the_architecture_column_is_kept_out_of_the_purl(fixtures):
    # rpm spells the tune arch core2_64 and deb spells it core2-64, and the
    # column changed from core2_64 to x86_64_v3 between these two releases.
    # Putting it in the purl would make identity depend on the backend.
    old, _ = parse(fixtures / "yocto-5.0.9")
    new, _ = parse(fixtures / "yocto-6.0.2", image="core-image-minimal")
    assert next(c for c in old if c.name == "busybox").purl == (
        next(c for c in new if c.name == "busybox").purl.replace("1.37.0", "1.36.1")
    )
    assert all("arch=" not in c.purl for c in old + new)


def test_git_versions_survive_intact(fixtures):
    components, _ = parse(fixtures / "yocto-5.0.9")
    kernel = next(c for c in components if c.name.startswith("kernel-image-bzimage"))
    assert kernel.version == "6.6.84+git0+917317e6b8_8dd317512c"


def test_the_image_manifest_carries_no_licenses(fixtures):
    # Not an oversight: the format has no license column, and inventing one
    # would be worse than leaving it out.
    components, _ = parse(fixtures / "yocto-5.0.9")
    assert all(c.license is None for c in components)
    assert all(c.supplier is None for c in components)


def test_a_malformed_line_names_the_file_and_line(tmp_path):
    manifest = tmp_path / "broken.manifest"
    manifest.write_text("busybox core2_64 1.36.1\nnot-enough-columns\n")
    with pytest.raises(YoctoParseError) as exc:
        parse_image_manifest(manifest)
    assert "broken.manifest:2" in str(exc.value)


def test_a_directory_without_a_manifest_is_reported(tmp_path):
    (tmp_path / "images" / "qemux86-64").mkdir(parents=True)
    with pytest.raises(YoctoParseError, match="no image or license manifest"):
        parse(tmp_path)


def test_ipk_and_deb_revisions_and_epochs_are_stripped():
    # The rpm backend reports "1.36.1"; deb and ipk report "1.36.1-r0" for the
    # very same package, and may prefix an epoch. An SBOM that changes when
    # PACKAGE_CLASSES changes is not usable for CVE matching.
    from sbom_embedded.parsers.yocto import normalize_version

    assert normalize_version("1.36.1") == "1.36.1"
    assert normalize_version("1.36.1-r0") == "1.36.1"
    assert normalize_version("2:1.36.1-r12") == "1.36.1"
    # The git suffix is part of PKGV and identifies the source revision.
    assert normalize_version("6.6.84+git0+917317e6b8_8dd317512c") == (
        "6.6.84+git0+917317e6b8_8dd317512c"
    )
    # An upstream version that merely looks like a revision must survive.
    assert normalize_version("1.2-rc1") == "1.2-rc1"


def test_a_pr_service_revision_is_stripped_like_a_plain_one():
    # PKGR is not "r<N>". bitbake.conf defines PKGR ?= "${PR}${EXTENDPRAUTO}",
    # and EXTENDPRAUTO is ".${PRAUTO}" whenever PRSERV_HOST is set, so the
    # dev-manual's own example packages are "...-r0.0" and "...-r0.1". A PR
    # service is the normal setup for a shared package feed, and leaving those
    # revisions in the version would reintroduce exactly the backend-dependent
    # SBOM this normalisation exists to prevent.
    from sbom_embedded.parsers.yocto import normalize_version

    assert normalize_version("1.0+git0+b6558dd387-r0.0") == "1.0+git0+b6558dd387"
    assert normalize_version("1.0+git1+dd2f5c3565-r0.1") == "1.0+git1+dd2f5c3565"
    # INC_PR: a .inc sets INC_PR = "r15" and the recipe PR = "${INC_PR}.0".
    # No PR service involved -- the dotted revision arrives on its own.
    assert normalize_version("3.3.2-r15.0") == "3.3.2"
    # A local PR server chained to an upstream one mints a dotted subvalue, and
    # bitbake's increase_revision() documents arbitrary depth ("1.2.3").
    assert normalize_version("1.36.1-r0.3.0") == "1.36.1"
    assert normalize_version("1.0-r0.1.2.3") == "1.0"
    # Epoch and a PR-service revision together.
    assert normalize_version("1:6.5-r0.2") == "6.5"


def test_a_version_that_merely_resembles_a_revision_is_left_alone():
    # The transform is lossy and runs on the license-manifest path too, where
    # the value is PV and carries no PKGR at all -- so every match there is a
    # false positive. These are the guards that keep it narrow: a digit is
    # required after the "r", and the match is anchored to the end.
    from sbom_embedded.parsers.yocto import normalize_version

    assert normalize_version("1.0-r1a") == "1.0-r1a"
    assert normalize_version("1.0-r") == "1.0-r"
    assert normalize_version("1.0-r0.") == "1.0-r0."
    # Only the trailing PKGR goes, even when PKGV itself ends in a revision.
    assert normalize_version("1.2-r3.4-r0") == "1.2-r3.4"
    # package_rpm.bbclass rewrites PKGV's "-" to "+", so this is what an rpm
    # manifest shows for a PKGV of "1.2-r1". Nothing to strip.
    assert normalize_version("1.2+r1") == "1.2+r1"
    # A legacy PR that is not "r<N>[.<N>...]" is carried through rather than
    # guessed at: PR:append = "+gitr${SRCREV}" was an OE-classic idiom.
    assert normalize_version("1.0-r0+gitr1a2b3c") == "1.0-r0+gitr1a2b3c"
    # Real recipe versions from current OE layers that contain a hyphen.
    for pv in ("2.1-3", "1.2.3-alt1", "0.3-beta15", "6.04-pre2", "1.3-20260721"):
        assert normalize_version(pv) == pv


def test_the_same_image_gives_the_same_purls_on_any_package_backend(tmp_path):
    rpm = tmp_path / "rpm.manifest"
    ipk = tmp_path / "ipk.manifest"
    # The same image again, built with a PR service configured: every revision
    # gains a ".<PRAUTO>" suffix. The purls must still not move.
    prserv = tmp_path / "prserv.manifest"
    rpm.write_text("busybox core2_64 1.36.1\nlibz1 core2_64 1.3.1\n")
    ipk.write_text("busybox core2-64 1.36.1-r0\nlibz1 core2-64 1:1.3.1-r0\n")
    prserv.write_text("busybox core2-64 1.36.1-r0.4\nlibz1 core2-64 1:1.3.1-r0.12\n")
    expected = [c.purl for c in parse_image_manifest(rpm)]
    assert [c.purl for c in parse_image_manifest(ipk)] == expected
    assert [c.purl for c in parse_image_manifest(prserv)] == expected


def test_an_empty_column_is_not_mistaken_for_a_malformed_line(tmp_path):
    # opkg_query initialises arch and version to "", so either can be empty.
    manifest = tmp_path / "sparse.manifest"
    manifest.write_text("noarch-pkg  1.0\ntrailing core2_64 \n")
    components = parse_image_manifest(manifest)
    assert [(c.name, c.version) for c in components] == [
        ("noarch-pkg", "1.0"),
        ("trailing", None),
    ]
    assert components[1].purl == "pkg:generic/trailing"


def test_an_empty_manifest_yields_no_components(tmp_path):
    # A zero-byte manifest is what an image with no packages produces.
    manifest = tmp_path / "empty.manifest"
    manifest.write_text("")
    assert parse_image_manifest(manifest) == []


def test_a_license_manifest_supplies_licenses_and_recipe_names(fixtures):
    components, label = parse(fixtures / "yocto-5.1-styhead")
    assert label == "core-image-minimal-qemux86-64"
    assert len(components) == 37

    libcrypto = next(c for c in components if c.name == "libcrypto")
    assert libcrypto.version == "3.3.1"
    assert libcrypto.license == "Apache-2.0"
    # The image manifest would have called this openssl package "libcrypto3"
    # and said nothing about openssl at all.
    assert libcrypto.properties == {"yocto:recipe": "openssl"}


def test_several_packages_can_share_one_recipe(fixtures):
    components, _ = parse(fixtures / "yocto-5.1-styhead")
    from_openssl = sorted(
        c.name for c in components if c.properties.get("yocto:recipe") == "openssl"
    )
    assert from_openssl == [
        "libcrypto",
        "openssl-conf",
        "openssl-ossl-module-legacy",
    ]


def test_non_spdx_license_operators_are_carried_through(fixtures):
    # Yocto joins licenses with "&", which is not SPDX. Dropping it would lose
    # half of a dual-licensed package's terms.
    components, _ = parse(fixtures / "yocto-5.1-styhead")
    busybox = next(c for c in components if c.name == "busybox")
    assert busybox.license == "GPL-2.0-only & bzip2-1.0.4"


def test_an_image_license_manifest_is_refused_with_an_explanation(fixtures):
    path = (
        fixtures
        / "yocto-5.1-styhead/licenses/qemux86_64"
        / "core-image-minimal-qemux86-64.rootfs-20250610090225"
        / "image_license.manifest"
    )
    with pytest.raises(YoctoParseError) as exc:
        parse_license_manifest(path)
    message = str(exc.value)
    assert "PACKAGE NAME" in message
    assert "image_license.manifest" in message


def test_the_license_manifest_wins_over_the_image_manifest(fixtures, tmp_path):
    # Both describe the same installed packages, but only one has licenses.
    image_dir = tmp_path / "images" / "qemux86-64"
    image_dir.mkdir(parents=True)
    (image_dir / "core-image-minimal-qemux86-64.rootfs.manifest").write_text(
        "libcrypto3 core2_64 3.3.1\n"
    )
    license_dir = (
        tmp_path / "licenses" / "qemux86_64" / "core-image-minimal-qemux86-64.rootfs"
    )
    license_dir.mkdir(parents=True)
    source = (
        fixtures
        / "yocto-5.1-styhead/licenses/qemux86_64"
        / "core-image-minimal-qemux86-64.rootfs-20250610090225"
        / "license.manifest"
    )
    (license_dir / "license.manifest").write_text(source.read_text())

    components, label = parse(tmp_path)
    assert label == "core-image-minimal-qemux86-64"
    assert len(components) == 37
    assert any(c.license for c in components)


def test_the_timestamped_directory_and_its_symlink_count_once(fixtures, tmp_path):
    source = (
        fixtures
        / "yocto-5.1-styhead/licenses/qemux86_64"
        / "core-image-minimal-qemux86-64.rootfs-20250610090225"
        / "license.manifest"
    )
    for name in (
        "core-image-minimal-qemux86-64.rootfs",
        "core-image-minimal-qemux86-64.rootfs-20250610090225",
    ):
        directory = tmp_path / "licenses" / "qemux86_64" / name
        directory.mkdir(parents=True)
        (directory / "license.manifest").write_text(source.read_text())

    components, _ = parse(tmp_path)
    assert len(components) == 37


def _license_block(name, version):
    return (
        f"PACKAGE NAME: {name}\n"
        f"PACKAGE VERSION: {version}\n"
        f"RECIPE NAME: {name}\n"
        "LICENSE: MIT\n\n"
    )


def _license_dir(root, *parts):
    directory = root.joinpath("licenses", *parts)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def test_a_rebuilt_deploy_reports_the_current_build_not_the_first(tmp_path):
    # bitbake never removes an old licenses/<image>-<machine>.rootfs-<DATETIME>
    # directory, so building twice leaves two that disagree. Keying on the
    # label and keeping whichever sorted first returned the OLDEST, because
    # %Y%m%d%H%M%S sorts chronologically -- a complete, plausible, schema-valid
    # package list describing firmware that is no longer on disk.
    for stamp, blocks in (
        ("20260101000000", _license_block("openssl", "3.0.0")),
        (
            "20260902171159",
            _license_block("openssl", "3.5.4") + _license_block("busybox", "1.37.0"),
        ),
    ):
        directory = _license_dir(
            tmp_path, "qemux86_64", f"core-image-minimal-qemux86-64.rootfs-{stamp}"
        )
        (directory / "license.manifest").write_text(blocks)

    components, _ = parse(tmp_path)
    assert sorted((c.name, c.version) for c in components) == [
        ("busybox", "1.37.0"),
        ("openssl", "3.5.4"),
    ]


def test_a_pre_4_3_license_directory_does_not_outrank_a_newer_one(tmp_path):
    # The arch level was added in 4.3. Upgrading poky in place without wiping
    # tmp/deploy leaves the old depth-1 directory beside the new depth-2 one,
    # and the depth-1 glob runs first -- so the pre-upgrade package list won
    # regardless of its timestamp.
    old = _license_dir(tmp_path, "core-image-minimal-qemux86-64-20240101000000")
    (old / "license.manifest").write_text(_license_block("openssl", "1.1.1"))
    new = _license_dir(
        tmp_path, "qemux86_64", "core-image-minimal-qemux86-64.rootfs-20260902171159"
    )
    (new / "license.manifest").write_text(_license_block("openssl", "3.5.4"))

    components, _ = parse(tmp_path)
    assert [(c.name, c.version) for c in components] == [("openssl", "3.5.4")]


def test_a_renamed_arch_directory_does_not_resurrect_an_old_build(tmp_path):
    # SSTATE_PKGARCH can change between builds, leaving two arch directories.
    # "core2-64" sorts before "qemux86_64", so the old build won on name order.
    old = _license_dir(
        tmp_path, "core2-64", "core-image-minimal-qemux86-64.rootfs-20240101000000"
    )
    (old / "license.manifest").write_text(_license_block("openssl", "1.1.1w"))
    new = _license_dir(
        tmp_path, "qemux86_64", "core-image-minimal-qemux86-64.rootfs-20260902171159"
    )
    (new / "license.manifest").write_text(_license_block("openssl", "3.5.4"))

    components, _ = parse(tmp_path)
    assert [(c.name, c.version) for c in components] == [("openssl", "3.5.4")]


def test_a_pre_4_3_symlink_does_not_outrank_a_current_layout(tmp_path):
    # Pre-4.3 bitbake wrote a stable licenses/<image>-<machine>/ symlink too.
    # After an in-place upgrade both it and the current
    # licenses/<arch>/<image>-<machine>.rootfs/ are untimestamped, so ranking
    # on the timestamp alone ties them -- and the depth-1 glob runs first, so
    # the pre-upgrade package list won. The arch level only exists from 4.3, so
    # the deeper directory is the one a newer bitbake wrote.
    old = _license_dir(tmp_path, "core-image-minimal-qemux86-64")
    (old / "license.manifest").write_text(_license_block("openssl", "1.1.1"))
    new = _license_dir(tmp_path, "qemux86_64", "core-image-minimal-qemux86-64.rootfs")
    (new / "license.manifest").write_text(_license_block("openssl", "3.5.4"))

    components, _ = parse(tmp_path)
    assert [(c.name, c.version) for c in components] == [("openssl", "3.5.4")]


def test_an_unreadable_image_directory_is_not_silently_skipped(tmp_path):
    # The 4.3+ manifest sits at licenses/<arch>/<image-dir>/, so it is the
    # <image-dir> level that has to be listable. Checking only two levels down
    # left the same silent fallback one directory further in.
    images = tmp_path / "images" / "qemux86-64"
    images.mkdir(parents=True)
    (images / "core-image-minimal-qemux86-64.rootfs.manifest").write_text(
        "busybox core2-64 1.36.1\n"
    )
    directory = _license_dir(
        tmp_path, "qemux86_64", "core-image-minimal-qemux86-64.rootfs-20260902171159"
    )
    (directory / "license.manifest").write_text(_license_block("busybox", "1.36.1"))

    directory.chmod(0o000)
    try:
        with pytest.raises(YoctoParseError, match="could not be read"):
            parse(tmp_path)
    finally:
        directory.chmod(0o755)


def test_the_symlink_wins_over_a_newer_timestamped_directory(tmp_path):
    # The symlink is the build system's own statement of which image is
    # current: it points at the last build that finished. A newer directory
    # left by a build that failed after writing licenses must not displace it.
    stale = _license_dir(
        tmp_path, "qemux86_64", "core-image-minimal-qemux86-64.rootfs-20260902171159"
    )
    (stale / "license.manifest").write_text(_license_block("openssl", "9.9.9"))
    good = _license_dir(
        tmp_path, "qemux86_64", "core-image-minimal-qemux86-64.rootfs-20260101000000"
    )
    (good / "license.manifest").write_text(_license_block("openssl", "3.5.4"))
    link = good.parent / "core-image-minimal-qemux86-64.rootfs"
    link.symlink_to(good.name, target_is_directory=True)

    components, _ = parse(tmp_path)
    assert [(c.name, c.version) for c in components] == [("openssl", "3.5.4")]


def test_a_block_line_without_a_key_is_reported(tmp_path):
    manifest = tmp_path / "license.manifest"
    manifest.write_text("PACKAGE NAME: busybox\nthis is not a key value line\n")
    with pytest.raises(YoctoParseError, match="KEY: value"):
        parse_license_manifest(manifest)


def test_a_fourth_field_is_rejected_rather_than_folded_into_the_version(tmp_path):
    # split(" ", 2) puts everything after the second space in the version.
    # Silently accepting it would yield pkg:generic/busybox@1.36.1%20extra.
    manifest = tmp_path / "extra.manifest"
    manifest.write_text("busybox core2_64 1.36.1 extra\n")
    with pytest.raises(YoctoParseError, match="contains a space"):
        parse_image_manifest(manifest)


def test_ambiguity_never_names_the_same_image_twice(fixtures, tmp_path):
    # A license directory that omits the machine suffix yields a label the
    # machine cannot be split off, so its short name collides with the image
    # manifest's. Listing short names would print one image name twice and
    # neither value would select anything.
    image_dir = tmp_path / "images" / "qemux86-64"
    image_dir.mkdir(parents=True)
    (image_dir / "core-image-minimal-qemux86-64.rootfs.manifest").write_text(
        "busybox core2_64 1.36.1\n"
    )
    license_dir = tmp_path / "licenses" / "qemux86_64" / "core-image-minimal"
    license_dir.mkdir(parents=True)
    source = (
        fixtures
        / "yocto-5.1-styhead/licenses/qemux86_64"
        / "core-image-minimal-qemux86-64.rootfs-20250610090225"
        / "license.manifest"
    )
    (license_dir / "license.manifest").write_text(source.read_text())

    with pytest.raises(YoctoParseError) as exc:
        parse(tmp_path)
    listed = str(exc.value).split("(")[1].split(")")[0].split(", ")
    assert len(listed) == len(set(listed)), listed
    # And each listed value must actually select something.
    for name in listed:
        components, _ = parse(tmp_path, image=name)
        assert components


def _write(directory, name, text):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(text)


def test_a_timestamped_image_manifest_is_skipped_in_favour_of_the_symlink(tmp_path):
    # Yocto writes both. Counting both would double every package in the SBOM.
    images = tmp_path / "images" / "qemux86-64"
    body = "busybox core2_64 1.36.1\n"
    _write(images, "core-image-minimal-qemux86-64.rootfs.manifest", body)
    _write(images, "core-image-minimal-qemux86-64.rootfs-20250610090225.manifest", body)

    assert [m.path.name for m in find_image_manifests(tmp_path)] == [
        "core-image-minimal-qemux86-64.rootfs.manifest"
    ]
    components, _ = parse(tmp_path)
    assert len(components) == 1


def test_a_debug_filesystem_manifest_is_skipped(tmp_path):
    images = tmp_path / "images" / "qemux86-64"
    _write(
        images,
        "core-image-minimal-qemux86-64.rootfs.manifest",
        "busybox core2_64 1.36.1\n",
    )
    _write(
        images,
        "core-image-minimal-qemux86-64.rootfs-dbg.manifest",
        "busybox-dbg core2_64 1.36.1\n",
    )

    components, label = parse(tmp_path)
    assert label == "core-image-minimal-qemux86-64"
    assert [c.name for c in components] == ["busybox"]


def test_a_whitespace_separator_line_does_not_silently_merge_two_packages(tmp_path):
    # A dict is last-wins, so merging two blocks would drop the first package
    # from the SBOM with a zero exit code -- the worst failure mode there is.
    manifest = tmp_path / "license.manifest"
    manifest.write_text(
        "PACKAGE NAME: busybox\nPACKAGE VERSION: 1.36.1\nLICENSE: GPL-2.0-only\n"
        " \n"
        "PACKAGE NAME: zlib\nPACKAGE VERSION: 1.3.1\nLICENSE: Zlib\n"
    )
    assert [c.name for c in parse_license_manifest(manifest)] == ["busybox", "zlib"]


def test_two_blocks_with_no_separator_are_reported_not_merged(tmp_path):
    manifest = tmp_path / "license.manifest"
    manifest.write_text(
        "PACKAGE NAME: busybox\nLICENSE: GPL-2.0-only\n"
        "PACKAGE NAME: zlib\nLICENSE: Zlib\n"
    )
    with pytest.raises(YoctoParseError, match="duplicate key"):
        parse_license_manifest(manifest)


def test_a_block_needs_only_a_package_name(tmp_path):
    # PACKAGE VERSION, RECIPE NAME and LICENSE are all optional in practice.
    manifest = tmp_path / "license.manifest"
    manifest.write_text("PACKAGE NAME: mystery\n")
    components = parse_license_manifest(manifest)
    assert components[0].name == "mystery"
    assert components[0].version is None
    assert components[0].properties == {}


def test_a_live_build_deploy_directory(fixtures):
    """The deploy directory of a bitbake run done on the development machine.

    Yocto 6.0.2, core-image-minimal, qemux86-64. Unlike every other Yocto
    fixture this one is a whole deploy tree from one build, with the directory
    names bitbake actually wrote.
    """
    components, label = parse(fixtures / "yocto-6.0.2-live")
    assert label == "core-image-minimal-qemux86-64"
    assert len(components) == 39
    assert all(c.license for c in components)
    assert all(c.properties.get("yocto:recipe") for c in components)

    libcrypto = next(c for c in components if c.name == "libcrypto")
    assert libcrypto.properties == {"yocto:recipe": "openssl"}


def test_the_license_manifest_is_preferred_over_the_image_manifest(fixtures):
    # Both are present in this fixture, from the same build. The image
    # manifest lists 37 packages and carries no licenses; the license manifest
    # lists 39 and carries licenses and recipe names.
    root = fixtures / "yocto-6.0.2-live"
    image_only = parse_image_manifest(
        root / "images/qemux86-64/core-image-minimal-qemux86-64.rootfs.manifest"
    )
    assert len(image_only) == 37
    assert all(c.license is None for c in image_only)

    components, _ = parse(root)
    assert len(components) == 39
    assert all(c.license for c in components)


def test_the_symlink_and_its_timestamped_target_count_once(fixtures):
    # bitbake writes core-image-minimal-qemux86-64.rootfs.manifest as a
    # symlink to ...rootfs-20260902171159.manifest and this fixture keeps
    # both, so a parser that globbed naively would double every package.
    manifests = find_image_manifests(fixtures / "yocto-6.0.2-live")
    assert [m.path.name for m in manifests] == [
        "core-image-minimal-qemux86-64.rootfs.manifest"
    ]


def test_the_two_manifests_disagree_about_package_names(fixtures):
    """Measured on one real build, which is why the parser never joins them.

    debian.bbclass renames library packages in the image manifest but not in
    the license manifest, and the two do not even list the same number of
    packages: the license manifest includes run-postinsts and
    util-linux-flock, which do not survive into the final rootfs.
    """
    root = fixtures / "yocto-6.0.2-live"
    image = {
        c.name
        for c in parse_image_manifest(
            root / "images/qemux86-64/core-image-minimal-qemux86-64.rootfs.manifest"
        )
    }
    licensed = {c.name for c in parse(root)[0]}

    assert len(image) == 37
    assert len(licensed) == 39
    # 11 of the 37 image-manifest names have no counterpart under that name.
    assert len(image - licensed) == 11
    for renamed in ("libc6", "libz1", "libcrypto3", "libkmod2", "liblzma5"):
        assert renamed in image
        assert renamed not in licensed
    for original in ("glibc", "zlib", "libcrypto", "libkmod", "liblzma"):
        assert original in licensed
        assert original not in image


def test_a_whitespace_only_package_name_is_rejected_clearly(tmp_path):
    # A tab is truthy, so `if not name` let it through and packageurl then
    # failed with "sequence item 4: expected str instance, NoneType found",
    # naming neither the file nor the line.
    manifest = tmp_path / "ws.manifest"
    manifest.write_text("\t x86_64 1.0\n")
    with pytest.raises(YoctoParseError, match="empty package name"):
        parse_image_manifest(manifest)


def test_an_enormous_line_does_not_become_an_enormous_error(tmp_path):
    # A 1 MB single-field line used to be echoed back whole, so a malformed
    # 100 MB manifest produced 100 MB of stderr.
    manifest = tmp_path / "huge.manifest"
    manifest.write_text("x" * 1_000_000 + "\n")
    with pytest.raises(YoctoParseError) as exc:
        parse_image_manifest(manifest)
    message = str(exc.value)
    assert len(message) < 500
    assert "1000000 chars" in message


def test_the_same_image_built_two_ways_gives_the_same_purls(fixtures):
    """The whole justification for stripping revisions and epochs, on real data.

    `yocto-6.0.2-live` and `yocto-6.0.2-ipk` are the same core-image-minimal
    for qemux86-64 from the same Yocto 6.0.2 tree, packaged with rpm and with
    ipk. Every ipk row carries a `-r0` and one carries an epoch; no rpm row
    carries either. If the normalisation were wrong, an SBOM of one image
    would not match an SBOM of the same image.
    """
    # Compared at the image-manifest level on both sides. parse() would pick
    # the live tree's license manifest, which lists pre-rename recipe-side
    # names (glibc, zlib) against the image manifest's libc6 and libz1 -- the
    # very mismatch test_the_two_manifests_must_not_be_joined_by_name pins.
    stem = "core-image-minimal-qemux86-64.rootfs.manifest"
    rpm = parse_image_manifest(fixtures / "yocto-6.0.2-live/images/qemux86-64" / stem)
    ipk = parse_image_manifest(fixtures / "yocto-6.0.2-ipk/images/qemux86-64" / stem)

    # The ipk image genuinely installs one package more; that is a difference
    # in image content, not in parsing.
    rpm_purls = {c.purl for c in rpm}
    ipk_purls = {c.purl for c in ipk}
    assert ipk_purls - rpm_purls == {"pkg:generic/util-linux-flock@2.41.3"}
    assert rpm_purls - ipk_purls == set()

    # netbase is the decisive row: "1:6.5-r0" in the ipk manifest, "6.5" in
    # the rpm one, and the same purl out of both.
    assert next(c for c in ipk if c.name == "netbase").purl == (
        next(c for c in rpm if c.name == "netbase").purl
    )


def test_the_raw_ipk_manifest_really_does_carry_revisions_and_an_epoch(fixtures):
    # Guards the fixture itself: if it were ever replaced by an rpm-backend
    # manifest, the test above would still pass and prove nothing.
    manifest = (
        fixtures
        / "yocto-6.0.2-ipk/images/qemux86-64"
        / "core-image-minimal-qemux86-64.rootfs.manifest"
    )
    rows = [line.split(" ", 2) for line in manifest.read_text().splitlines() if line]
    assert len(rows) == 38
    # Every row carries a revision, and not all of them are -r0: two are -r1,
    # so the fixture exercises more than the trivial case.
    assert all(re.search(r"-r\d+$", version) for _, _, version in rows)
    assert {v.rsplit("-r", 1)[1] for _, _, v in rows} == {"0", "1"}
    assert any(version.startswith("1:") for _, _, version in rows)
    # Hyphenated tune arch is the ipk/deb spelling; rpm writes underscores.
    assert any(arch == "x86-64-v3" for _, arch, _ in rows)


def test_a_byte_order_mark_does_not_become_part_of_the_first_package_name(tmp_path):
    # U+FEFF is category Cf, not whitespace, so str.strip() leaves it and the
    # emptiness guard passes: the first package came out named "\ufeffbase-files"
    # with a purl nothing can resolve, at exit 0. buildroot.py already read
    # utf-8-sig for exactly this reason; the Yocto paths did not.
    manifest = tmp_path / "img-qemux86-64.manifest"
    manifest.write_bytes(
        b"\xef\xbb\xbfbase-files qemux86_64 3.0.14\nbusybox x86_64 1.37.0\n"
    )
    assert [c.name for c in parse_image_manifest(manifest)] == ["base-files", "busybox"]


def test_a_byte_order_mark_does_not_hide_the_package_name_key(tmp_path):
    # The same BOM turned "PACKAGE NAME" into "\ufeffPACKAGE NAME", which failed
    # the key check and produced an actively wrong diagnosis: the file was
    # reported as an image_license.manifest, which it is not.
    manifest = tmp_path / "license.manifest"
    manifest.write_bytes(
        b"\xef\xbb\xbfPACKAGE NAME: libcrypto\nPACKAGE VERSION: 3.3.2\n"
    )
    components = parse_license_manifest(manifest)
    assert [(c.name, c.version) for c in components] == [("libcrypto", "3.3.2")]


def test_an_enormous_block_key_does_not_become_an_enormous_error(tmp_path):
    # _excerpt() bounds every other interpolation in this file; these two paths
    # bypassed it and echoed megabytes of input back to stderr.
    manifest = tmp_path / "license.manifest"
    manifest.write_text("X" * 200_000 + ": value\n")
    with pytest.raises(YoctoParseError) as exc:
        parse_license_manifest(manifest)
    assert len(str(exc.value)) < 1_000


def test_an_enormous_duplicate_key_does_not_become_an_enormous_error(tmp_path):
    manifest = tmp_path / "license.manifest"
    key = "K" * 200_000
    manifest.write_text(f"PACKAGE NAME: a\n{key}: 1\n{key}: 2\n")
    with pytest.raises(YoctoParseError) as exc:
        parse_license_manifest(manifest)
    assert len(str(exc.value)) < 1_000


def test_a_license_directory_that_cannot_be_read_is_not_silently_skipped(tmp_path):
    # Path.glob reports a directory it may not read as no matches, so discovery
    # found no license manifest, fell back to the image manifest, and emitted a
    # complete-looking SBOM with no licenses and no recipe names at exit 0.
    images = tmp_path / "images" / "qemux86-64"
    images.mkdir(parents=True)
    (images / "core-image-minimal-qemux86-64.rootfs.manifest").write_text(
        "busybox core2-64 1.36.1\n"
    )
    arch = tmp_path / "licenses" / "qemux86_64"
    directory = arch / "core-image-minimal-qemux86-64.rootfs-20260902171159"
    directory.mkdir(parents=True)
    (directory / "license.manifest").write_text(_license_block("busybox", "1.36.1"))

    arch.chmod(0o000)
    try:
        with pytest.raises(YoctoParseError, match="could not be read"):
            parse(tmp_path)
    finally:
        arch.chmod(0o755)


def test_a_license_manifest_name_with_no_purl_form_is_rejected(tmp_path):
    # The image-manifest branch of this guard has a test; this one did not, so
    # deleting it restored the rich traceback on the license path alone.
    manifest = tmp_path / "license.manifest"
    manifest.write_text("PACKAGE NAME: /\nPACKAGE VERSION: 1.0\n")
    with pytest.raises(YoctoParseError, match="has no purl form"):
        parse_license_manifest(manifest)


def test_a_block_naming_thousands_of_keys_does_not_flood_stderr(tmp_path):
    # _excerpt caps one enormous key; nothing capped a huge number of small
    # ones, and the sum was proportional to the file after all.
    manifest = tmp_path / "license.manifest"
    manifest.write_text("".join(f"K{i}{'X' * 300}: v\n" for i in range(3000)))
    with pytest.raises(YoctoParseError) as exc:
        parse_license_manifest(manifest)
    assert len(str(exc.value)) < 2_000


def test_one_image_losing_its_licenses_is_not_masked_by_another(tmp_path):
    # A deploy normally holds several images -- that is why --image exists.
    # Gating the unreadable-directory check on "no license manifest anywhere"
    # meant one image's readable directory hid another image's blocked one, and
    # the SBOM for the image actually asked for came out at exit 0 with every
    # licence and recipe name missing.
    images = tmp_path / "images" / "qemux86-64"
    images.mkdir(parents=True)
    for image in ("core-image-minimal", "core-image-full-cmdline"):
        (images / f"{image}-qemux86-64.rootfs.manifest").write_text(
            "busybox core2-64 1.36.1\n"
        )
        directory = _license_dir(tmp_path, "x86_64", f"{image}-qemux86-64.rootfs")
        (directory / "license.manifest").write_text(_license_block("busybox", "1.36.1"))

    blocked = (
        tmp_path / "licenses" / "x86_64" / "core-image-full-cmdline-qemux86-64.rootfs"
    )
    blocked.chmod(0o000)
    try:
        with pytest.raises(YoctoParseError, match="could not be read"):
            parse(tmp_path, image="core-image-full-cmdline")
    finally:
        blocked.chmod(0o755)


def test_a_stale_unreadable_rebuild_directory_does_not_stop_a_good_build(tmp_path):
    # The converse of the test above: once this image's current licence
    # directory has been read, an older one nobody can open is irrelevant and
    # must not turn a perfectly good deploy into an error.
    good = _license_dir(
        tmp_path, "x86_64", "core-image-minimal-qemux86-64.rootfs-20260902171159"
    )
    (good / "license.manifest").write_text(_license_block("busybox", "1.36.1"))
    stale = _license_dir(
        tmp_path, "x86_64", "core-image-minimal-qemux86-64.rootfs-20240101000000"
    )
    (stale / "license.manifest").write_text(_license_block("busybox", "1.0.0"))

    stale.chmod(0o000)
    try:
        components, _ = parse(tmp_path)
    finally:
        stale.chmod(0o755)
    assert [(c.name, c.version) for c in components] == [("busybox", "1.36.1")]


def test_a_renamed_arch_is_resolved_through_the_symlink_target(tmp_path):
    # Two arch directories, each holding an untimestamped symlink for the same
    # image. Nothing in either directory name says which build is current --
    # but the symlinks resolve to timestamped targets, and those do.
    newest = None
    for arch, stamp, version in (
        ("core2-64", "20240101000000", "1.1.1w"),
        ("qemux86_64", "20260902171159", "3.5.4"),
    ):
        target = _license_dir(
            tmp_path, arch, f"core-image-minimal-qemux86-64.rootfs-{stamp}"
        )
        (target / "license.manifest").write_text(_license_block("openssl", version))
        link = target.parent / "core-image-minimal-qemux86-64.rootfs"
        link.symlink_to(target.name, target_is_directory=True)
        newest = version

    components, _ = parse(tmp_path)
    assert [(c.name, c.version) for c in components] == [("openssl", newest)]

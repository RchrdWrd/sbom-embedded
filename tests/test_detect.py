import pytest

from sbom_embedded.parsers.detect import BuildSystem, DetectionError, detect


def test_a_yocto_deploy_directory_is_recognised(fixtures):
    found = detect(fixtures / "yocto-5.0.9")
    assert found.system is BuildSystem.YOCTO
    assert found.root == fixtures / "yocto-5.0.9"


def test_a_buildroot_output_directory_is_recognised(fixtures):
    found = detect(fixtures / "buildroot-2023.02")
    assert found.system is BuildSystem.BUILDROOT
    # Detection resolves down to the directory the parser wants.
    assert found.root == fixtures / "buildroot-2023.02" / "legal-info"


def test_the_legal_info_directory_itself_is_also_accepted(fixtures):
    found = detect(fixtures / "buildroot-2023.02" / "legal-info")
    assert found.system is BuildSystem.BUILDROOT


def test_a_yocto_build_tree_resolves_down_to_the_deploy_directory(tmp_path):
    # Someone who points at the build directory rather than tmp/deploy.
    images = tmp_path / "tmp" / "deploy" / "images" / "qemux86-64"
    images.mkdir(parents=True)
    (images / "core-image-minimal-qemux86-64.rootfs.manifest").write_text(
        "busybox core2_64 1.36.1\n"
    )
    found = detect(tmp_path)
    assert found.system is BuildSystem.YOCTO
    assert found.root == tmp_path / "tmp" / "deploy"


def test_a_deploy_with_only_license_manifests_is_still_yocto(fixtures):
    # A build that kept its licenses but not its images is readable, and the
    # license manifest is the better source anyway.
    found = detect(fixtures / "yocto-5.1-styhead")
    assert found.system is BuildSystem.YOCTO


def test_an_images_directory_without_manifests_is_not_yocto(tmp_path):
    # Detection must not succeed where parsing would then fail.
    (tmp_path / "images" / "qemux86-64").mkdir(parents=True)
    with pytest.raises(DetectionError, match="neither"):
        detect(tmp_path)


def test_a_directory_holding_both_is_refused_rather_than_guessed(tmp_path):
    images = tmp_path / "images" / "qemux86-64"
    images.mkdir(parents=True)
    (images / "img-qemux86-64.manifest").write_text("busybox core2_64 1.36.1\n")
    (tmp_path / "manifest.csv").write_text("PACKAGE,VERSION,LICENSE\nfoo,1,MIT\n")
    with pytest.raises(DetectionError, match="both"):
        detect(tmp_path)


def test_a_missing_path_is_reported(tmp_path):
    with pytest.raises(DetectionError, match="does not exist"):
        detect(tmp_path / "nope")


def test_a_file_that_is_not_a_manifest_is_refused(tmp_path):
    target = tmp_path / "sbom.json"
    target.write_text("{}")
    with pytest.raises(DetectionError, match=r"only manifest\.csv"):
        detect(target)


def test_the_buildroot_manifest_can_be_given_directly(fixtures):
    # `buildroot.find_manifest` documents this and has always supported it;
    # nothing reached that branch, because detect() refused every
    # non-directory first.
    manifest = fixtures / "buildroot-2023.02" / "legal-info" / "manifest.csv"
    found = detect(manifest)
    assert found.system is BuildSystem.BUILDROOT
    assert found.root == manifest


def test_a_host_manifest_given_directly_is_refused(tmp_path):
    # Same columns and the same parser, but it lists the build host's tools.
    # Accepting any file by path would have put ccache and pkgconf into the
    # firmware's SBOM -- exactly what buildroot.py declines to do.
    host = tmp_path / "host-manifest.csv"
    host.write_text("PACKAGE,VERSION,LICENSE\nccache,4.10,GPL-3.0\n")
    with pytest.raises(DetectionError, match=r"only manifest\.csv"):
        detect(host)


def test_a_complete_buildroot_output_tree_is_not_mistaken_for_yocto(tmp_path):
    """Reproduces the shape of a real, fully built Buildroot output directory.

    Verified against an actual `make` run of Buildroot 2026.08-rc3: that tree
    held 867,355 files and ten-odd files named `*.manifest`, all of them
    Windows application manifests shipped inside host package sources
    (host-python3, host-cmake, host-ninja, host-m4, gcc). None sits at
    `images/<something>/*.manifest`, which is why Yocto detection does not
    fire -- but the margin is one directory level, so it is worth pinning.
    """
    output = tmp_path / "output"
    (output / "legal-info").mkdir(parents=True)
    (output / "legal-info" / "manifest.csv").write_text(
        '"PACKAGE","VERSION","LICENSE"\n"busybox","1.38.0","GPL-2.0"\n'
    )
    # Buildroot writes images straight into images/, never into a per-machine
    # subdirectory the way Yocto does.
    (output / "images").mkdir()
    (output / "images" / "rootfs.tar").write_text("")
    (output / "images" / "rootfs.ext2").write_text("")

    for stray in (
        "build/host-python3-3.14.7/PC/python.manifest",
        "build/host-cmake-4.4.0/Source/cmake.version.manifest",
        "build/host-ninja-1.13.2/windows/ninja.manifest",
        "build/gcc-final-15.3.0/gcc/config/i386/winnt-utf8.manifest",
    ):
        path = output / stray
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("")

    for start in (output, tmp_path):
        found = detect(start)
        assert found.system is BuildSystem.BUILDROOT, start
        assert found.root == output / "legal-info", start


def test_a_directory_we_cannot_read_is_named_rather_than_called_empty(tmp_path):
    # An unreadable directory looks exactly like an empty one to glob, so the
    # generic message sent the user hunting for files that were sitting there.
    machine = tmp_path / "images" / "qemux86-64"
    machine.mkdir(parents=True)
    (machine / "core-image-minimal-qemux86-64.rootfs.manifest").write_text(
        "busybox core2-64 1.36.1\n"
    )
    machine.chmod(0o000)
    try:
        with pytest.raises(DetectionError) as exc:
            detect(tmp_path)
    finally:
        machine.chmod(0o755)
    assert "could not be read" in str(exc.value)
    assert str(machine) in str(exc.value)


def test_a_blocked_license_image_directory_is_named_too(tmp_path):
    # The deepest evidence pattern is licenses/<arch>/<image>/license.manifest,
    # so ruling it out needs four directory levels listable. Checking three
    # left the current Yocto layout reporting "not a build directory at all".
    directory = (
        tmp_path / "licenses" / "x86_64" / "core-image-minimal-qemux86-64.rootfs"
    )
    directory.mkdir(parents=True)
    (directory / "license.manifest").write_text("PACKAGE NAME: busybox\n")
    directory.chmod(0o000)
    try:
        with pytest.raises(DetectionError) as exc:
            detect(tmp_path)
    finally:
        directory.chmod(0o755)
    assert "could not be read" in str(exc.value)
    assert str(directory) in str(exc.value)

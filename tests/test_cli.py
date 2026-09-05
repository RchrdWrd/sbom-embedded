import json
import os
from importlib.metadata import version

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from typer.testing import CliRunner

from sbom_embedded.cli import app

runner = CliRunner()


def run(*args):
    return runner.invoke(app, [str(a) for a in args])


def test_the_documented_usage_writes_valid_cyclonedx_to_stdout(fixtures):
    result = run(fixtures / "yocto-5.0.9")
    assert result.exit_code == 0
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(result.stdout) is None
    doc = json.loads(result.stdout)
    assert len(doc["components"]) == 36
    assert doc["metadata"]["component"]["name"] == "core-image-minimal-qemux86-64"


def test_a_buildroot_directory_needs_no_extra_flags(fixtures):
    result = run(fixtures / "buildroot-2023.02")
    assert result.exit_code == 0
    doc = json.loads(result.stdout)
    assert [c["name"] for c in doc["components"]] == [
        "busybox",
        "glibc",
        "linux",
        "linux-headers",
        "rpi-firmware",
    ]


def test_every_component_of_every_fixture_has_a_purl(fixtures):
    for directory in sorted(p for p in fixtures.iterdir() if p.is_dir()):
        args = [directory]
        if directory.name == "yocto-6.0.2":
            args += ["--image", "core-image-minimal"]
        result = run(*args)
        assert result.exit_code == 0, directory
        doc = json.loads(result.stdout)
        assert doc["components"], directory
        missing = [c["name"] for c in doc["components"] if not c.get("purl")]
        assert missing == [], f"{directory}: {missing}"


def test_an_ambiguous_deploy_directory_exits_nonzero_with_advice(fixtures):
    result = run(fixtures / "yocto-6.0.2")
    assert result.exit_code == 1
    assert "--image" in result.output
    assert not result.stdout.startswith("{")


def test_the_product_name_can_be_overridden(fixtures):
    result = run(fixtures / "buildroot-2023.02", "--name", "acme-router-v2")
    assert result.exit_code == 0
    assert json.loads(result.stdout)["metadata"]["component"]["name"] == (
        "acme-router-v2"
    )


def test_image_selection_is_refused_for_buildroot(fixtures):
    result = run(fixtures / "buildroot-2023.02", "--image", "whatever")
    assert result.exit_code != 0
    assert "Yocto" in result.output


def test_output_can_go_to_a_file_leaving_stdout_clean(fixtures, tmp_path):
    target = tmp_path / "sbom.json"
    result = run(fixtures / "yocto-5.0.9", "-o", target)
    assert result.exit_code == 0
    assert result.stdout == ""
    assert len(json.loads(target.read_text())["components"]) == 36


def test_an_unrecognised_directory_exits_nonzero(tmp_path):
    result = run(tmp_path)
    assert result.exit_code == 1
    assert "neither" in result.output


def test_an_empty_package_list_is_warned_about_not_emitted_silently(tmp_path):
    # A valid but empty SBOM is the worst possible compliance artifact: it
    # reads as a clean result.
    images = tmp_path / "images" / "qemux86-64"
    images.mkdir(parents=True)
    (images / "img-qemux86-64.manifest").write_text("")
    result = run(tmp_path)
    assert result.exit_code == 0
    assert "warning" in result.output
    assert json.loads(result.stdout).get("components", []) == []


def test_stdout_ends_with_a_newline(fixtures):
    result = run(fixtures / "buildroot-2023.02")
    assert result.stdout.endswith("}\n")


def test_an_unwritable_output_path_reports_instead_of_traceback(fixtures, tmp_path):
    target = tmp_path / "missing-directory" / "sbom.json"
    result = run(fixtures / "buildroot-2023.02", "-o", target)
    assert result.exit_code == 1
    assert "cannot write" in result.output
    assert "Traceback" not in result.output


def test_dependency_references_resolve_on_every_fixture(fixtures):
    # The unit tests cover this on synthetic components; this proves it on
    # every real manifest the repository has.
    for directory in sorted(p for p in fixtures.iterdir() if p.is_dir()):
        args = [directory]
        if directory.name == "yocto-6.0.2":
            args += ["--image", "core-image-minimal"]
        result = run(*args)
        assert result.exit_code == 0, directory
        doc = json.loads(result.stdout)

        known = {c["bom-ref"] for c in doc["components"]}
        assert known == {c["purl"] for c in doc["components"]}, directory
        known.add(doc["metadata"]["component"]["bom-ref"])

        for entry in doc["dependencies"]:
            assert entry["ref"] in known, (directory, entry["ref"])
            for ref in entry.get("dependsOn", []):
                assert ref in known, (directory, ref)


def test_the_product_version_is_absent_unless_given(fixtures):
    # No manifest records a product version. Writing "0.0.0" or a date would
    # be invented data in a compliance artifact.
    result = run(fixtures / "buildroot-2023.02")
    assert result.exit_code == 0
    assert "version" not in json.loads(result.stdout)["metadata"]["component"]


def test_the_product_version_reaches_the_root_component(fixtures):
    result = run(
        fixtures / "buildroot-2023.02",
        "--name",
        "acme-router",
        "--product-version",
        "2.4.1",
    )
    assert result.exit_code == 0
    root = json.loads(result.stdout)["metadata"]["component"]
    assert root["name"] == "acme-router"
    assert root["version"] == "2.4.1"


def test_a_non_utf8_manifest_reports_instead_of_a_traceback(tmp_path):
    # A single bad byte used to escape read_text() as a rich traceback,
    # breaking the documented "error: ... , exit 1" contract.
    images = tmp_path / "images" / "qemux86-64"
    images.mkdir(parents=True)
    (images / "img-qemux86-64.manifest").write_bytes(b"busybox core2_64 1.36.1\n\xff\n")
    result = run(tmp_path)
    assert result.exit_code == 1
    assert "cannot read" in result.output
    assert "Traceback" not in result.output


def test_an_unreadable_manifest_reports_instead_of_a_traceback(tmp_path):
    legal = tmp_path / "legal-info"
    legal.mkdir()
    manifest = legal / "manifest.csv"
    manifest.write_text('"PACKAGE","VERSION","LICENSE"\n"busybox","1.38.0","GPL-2.0"\n')
    manifest.chmod(0o000)
    try:
        result = run(tmp_path)
    finally:
        manifest.chmod(0o644)
    assert result.exit_code == 1
    assert "cannot read" in result.output
    assert "Traceback" not in result.output


def test_a_non_utf8_buildroot_manifest_reports_instead_of_a_traceback(tmp_path):
    legal = tmp_path / "legal-info"
    legal.mkdir()
    (legal / "manifest.csv").write_bytes(
        b'"PACKAGE","VERSION","LICENSE"\n"busy\xffbox","1.38.0","GPL-2.0"\n'
    )
    result = run(tmp_path)
    assert result.exit_code == 1
    assert "cannot read" in result.output
    assert "Traceback" not in result.output


def test_a_package_name_with_no_purl_form_reports_instead_of_a_traceback(tmp_path):
    # "/" is not blank, so the emptiness guards let it through; packageurl then
    # normalises it away and dies inside "".join() with a TypeError that
    # cli.py's except clause does not list. That reached the user as a 5 KB
    # rich traceback quoting absolute paths -- the outcome SECURITY.md's threat
    # model names explicitly as in scope.
    legal = tmp_path / "legal-info"
    legal.mkdir()
    (legal / "manifest.csv").write_text("PACKAGE,VERSION,LICENSE\n/,1.0,MIT\n")
    result = run(tmp_path)
    assert result.exit_code == 1
    assert "has no purl form" in result.output
    assert "Traceback" not in result.output


def test_a_slash_only_name_in_a_yocto_manifest_is_reported_with_its_line(tmp_path):
    images = tmp_path / "images" / "qemux86-64"
    images.mkdir(parents=True)
    (images / "img-qemux86-64.manifest").write_text(
        "busybox core2_64 1.36.1\n/ core2_64 1.0\n"
    )
    result = run(tmp_path)
    assert result.exit_code == 1
    assert "img-qemux86-64.manifest:2" in result.output
    assert "has no purl form" in result.output
    assert "Traceback" not in result.output


def test_a_repeated_row_is_collapsed_and_reported(tmp_path):
    # Re-running `make <pkg>-legal-info` appends to the existing manifest.csv,
    # so the same row can appear twice. Both copies say the same thing and the
    # image holds one of that package -- but two components sharing a purl made
    # the library invent a random bom-ref for the second and leave it out of
    # the dependency graph entirely.
    legal = tmp_path / "legal-info"
    legal.mkdir()
    (legal / "manifest.csv").write_text(
        "PACKAGE,VERSION,LICENSE\n"
        "busybox,1.36.1,GPL-2.0\n"
        "busybox,1.36.1,GPL-2.0\n"
        "zlib,1.3.1,Zlib\n"
    )
    result = run(tmp_path)
    assert result.exit_code == 0
    assert "appears 2 times" in result.output
    doc = json.loads(result.stdout)
    assert [c["bom-ref"] for c in doc["components"]] == [
        "pkg:generic/busybox@1.36.1",
        "pkg:generic/zlib@1.3.1",
    ]
    root = next(e for e in doc["dependencies"] if e["ref"] == "buildroot")
    assert sorted(root["dependsOn"]) == [
        "pkg:generic/busybox@1.36.1",
        "pkg:generic/zlib@1.3.1",
    ]


def test_two_rows_that_contradict_each_other_are_refused(tmp_path):
    # Same purl, different licence: nothing here can say which is right, and
    # picking one would put invented data into a compliance document.
    legal = tmp_path / "legal-info"
    legal.mkdir()
    (legal / "manifest.csv").write_text(
        "PACKAGE,VERSION,LICENSE\nbusybox,1.36.1,GPL-2.0\nbusybox,1.36.1,MIT\n"
    )
    result = run(tmp_path)
    assert result.exit_code == 1
    assert "disagree on license" in result.output
    assert "Traceback" not in result.output


def test_a_product_name_colliding_with_a_component_is_refused(fixtures):
    # The root shares the bom-ref namespace with every component, and --name
    # puts its ref entirely under the user's control.
    result = run(fixtures / "buildroot-2023.02", "--name", "pkg:generic/busybox@1.36.1")
    assert result.exit_code == 1
    assert "pass a different --name" in result.output
    assert "Traceback" not in result.output


def test_the_written_count_matches_what_the_document_holds(tmp_path):
    legal = tmp_path / "legal-info"
    legal.mkdir()
    (legal / "manifest.csv").write_text(
        "PACKAGE,VERSION,LICENSE\nbusybox,1.36.1,GPL-2.0\nbusybox,1.36.1,GPL-2.0\n"
    )
    out = tmp_path / "sbom.json"
    result = run(tmp_path, "-o", out)
    assert result.exit_code == 0
    assert "wrote 1 components" in result.output
    assert len(json.loads(out.read_text())["components"]) == 1


def test_the_reported_version_is_the_packaged_one():
    # __version__ is hand-maintained and feeds both `--version` and every
    # SBOM's metadata.tools entry, so a forgotten bump would misattribute every
    # document the release produces. The publish workflow already refuses a tag
    # that disagrees with the distribution; this ties the third copy to it.
    from sbom_embedded import __version__

    assert __version__ == version("sbom-embedded")
    result = run("--version")
    assert result.exit_code == 0
    assert result.stdout.strip() == f"sbom-embedded {__version__}"


def test_a_failed_write_leaves_the_previous_document_intact(fixtures, tmp_path):
    # Path.write_text truncates the destination and only then writes, so a
    # failure part-way left a truncated file where a good SBOM had been -- and
    # that file is not valid JSON. The exit code said the run failed; the
    # artifact beside it said otherwise.
    output = tmp_path / "sbom.json"
    output.write_text('{"previous": true}')

    def no_space(*args, **kwargs):
        raise OSError(28, "No space left on device")

    original = os.fsync
    os.fsync = no_space
    try:
        result = run(fixtures / "buildroot-2026.08", "-o", output)
    finally:
        os.fsync = original

    assert result.exit_code == 1
    assert "cannot write" in result.output
    assert json.loads(output.read_text()) == {"previous": True}
    # And nothing half-written left behind under a temporary name.
    assert [p.name for p in tmp_path.iterdir()] == ["sbom.json"]


def test_the_written_file_is_as_readable_as_any_other(fixtures, tmp_path):
    # The write goes through a temporary file, which is created 0600. Without
    # matching what write_text would have produced, replacing an SBOM would
    # quietly narrow who can read it.
    output = tmp_path / "sbom.json"
    reference = tmp_path / "reference.json"
    reference.write_text("{}")
    assert run(fixtures / "buildroot-2023.02", "-o", output).exit_code == 0
    assert output.stat().st_mode == reference.stat().st_mode


def test_the_buildroot_manifest_can_be_given_directly(fixtures):
    manifest = fixtures / "buildroot-2026.08" / "legal-info" / "manifest.csv"
    result = run(manifest)
    assert result.exit_code == 0
    assert len(json.loads(result.stdout)["components"]) == 44


def test_a_host_manifest_given_directly_is_refused(tmp_path):
    host = tmp_path / "host-manifest.csv"
    host.write_text("PACKAGE,VERSION,LICENSE\nccache,4.10,GPL-3.0\n")
    result = run(host)
    assert result.exit_code == 1
    assert "only manifest.csv" in result.output
    assert "Traceback" not in result.output

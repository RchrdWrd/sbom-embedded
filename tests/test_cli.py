import json

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

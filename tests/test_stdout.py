"""How the tool behaves when writing to stdout goes wrong.

These cannot go through typer's CliRunner, which replaces stdout with an
in-memory buffer: a broken pipe, a closed descriptor and a failing write only
exist in a real process. Each of them used to leave the documented contract --
`error: <message>` on stderr and exit 1 -- and produce a traceback, a silent
exit 1, or exit 120 from the interpreter's own shutdown flush.
"""

import shlex
import subprocess
import sys
import textwrap

import pytest

from .support import FIXTURES

# Large enough to exceed a 64 KB pipe buffer, so the write cannot quietly
# succeed before anyone notices the reader is gone.
BIG = FIXTURES / "yocto-6.0.2"
BIG_ARGS = [str(BIG), "--image", "core-image-full-cmdline"]

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX descriptor and rlimit semantics"
)


def _child(preamble: str = "") -> str:
    return textwrap.dedent(preamble) + "from sbom_embedded.cli import app\napp()\n"


@posix_only
def test_a_reader_that_goes_away_is_not_reported_as_a_tool_error():
    # `sbom-embedded ... | head` exited 1 with an empty stderr, colliding with
    # the code reserved for `error: <message>`, and only once the document
    # outgrew the pipe buffer -- so it looked nondeterministic.
    process = subprocess.Popen(
        [sys.executable, "-c", _child(), *BIG_ARGS],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    process.stdout.close()
    stderr = process.stderr.read() if process.stderr else b""
    # 128 + SIGPIPE, what a shell utility reports, and distinct from 1.
    assert process.wait() == 141
    assert stderr == b""


@posix_only
def test_a_closed_stdout_reports_instead_of_a_traceback(tmp_path):
    script = tmp_path / "run.py"
    script.write_text(_child())
    # shlex.quote, not bare interpolation: a checkout or temp path containing
    # a space would otherwise split into two arguments and the test would fail
    # for a reason that has nothing to do with what it is testing.
    argv = " ".join(shlex.quote(a) for a in [sys.executable, str(script), *BIG_ARGS])
    result = subprocess.run(
        f"exec {argv} >&-",
        shell=True,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "error:" in result.stderr
    assert "Traceback" not in result.stderr


@posix_only
def test_a_failing_write_is_reported_in_the_documented_form(tmp_path):
    # Without an explicit flush the failure surfaced only when CPython flushed
    # at interpreter shutdown, after this command had already returned: exit
    # 120 with "Exception ignored while flushing sys.stdout".
    script = tmp_path / "run.py"
    script.write_text(
        _child(
            """
            import resource, signal
            resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            """
        )
    )
    with (tmp_path / "out.json").open("w") as handle:
        result = subprocess.run(
            [sys.executable, str(script), *BIG_ARGS],
            stdout=handle,
            stderr=subprocess.PIPE,
            text=True,
        )
    assert result.returncode == 1
    assert "error: cannot write to stdout" in result.stderr
    assert "Exception ignored" not in result.stderr

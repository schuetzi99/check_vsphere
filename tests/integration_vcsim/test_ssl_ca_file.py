import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_for_port(host, port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            try:
                sock.connect((host, port))
                return
            except OSError:
                time.sleep(0.1)

    raise RuntimeError("vcsim did not become ready in time")


def _get_vcsim_cert(host, port):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
            return cert_pem


@pytest.fixture
def vcsim_server_with_tls():
    vcsim = subprocess.run(
        ["which", "vcsim"], capture_output=True, text=True
    ).stdout.strip()
    if not vcsim:
        pytest.skip("vcsim binary not found in PATH")

    host = "127.0.0.1"
    port = _find_free_port()

    proc = subprocess.Popen(
        [vcsim, "-l", "{}:{}".format(host, port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        _wait_for_port(host, port)
    except Exception:
        proc.terminate()
        proc.wait(timeout=5)
        raise

    yield {"host": host, "port": port, "proc": proc}

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


@pytest.fixture
def temp_ca_cert(vcsim_server_with_tls):
    cert_pem = _get_vcsim_cert(
        vcsim_server_with_tls["host"],
        vcsim_server_with_tls["port"]
    )

    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f:
        f.write(cert_pem)
        cert_path = f.name

    yield cert_path

    os.unlink(cert_path)


@pytest.fixture
def run_cli():
    def _run(args, timeout=30, env=None):
        cmd = [sys.executable, "-m", "checkvsphere.cli"] + list(args)
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)

        return subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            env=merged_env,
            timeout=timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )

    return _run


def test_about_with_ssl_ca_file(run_cli, vcsim_server_with_tls, temp_ca_cert):
    result = run_cli(
        [
            "about",
            "-s", vcsim_server_with_tls["host"],
            "-o", str(vcsim_server_with_tls["port"]),
            "-u", "user",
            "-p", "pass",
        ],
        env={"SSL_CA_FILE": temp_ca_cert}
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK:" in result.stdout
    assert "govmomi simulator" in result.stdout


def test_about_with_custom_ca_dir(run_cli, vcsim_server_with_tls, temp_ca_cert):
    pytest.skip(
        "SSL_CA_PATH requires OpenSSL-style hashed cert directory, "
        "which cannot be easily created without openssl command"
    )


def test_about_without_ssl_verification_still_works(run_cli, vcsim_server_with_tls):
    result = run_cli(
        [
            "about",
            "-s", vcsim_server_with_tls["host"],
            "-o", str(vcsim_server_with_tls["port"]),
            "-u", "user",
            "-p", "pass",
            "-nossl",
        ]
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK:" in result.stdout
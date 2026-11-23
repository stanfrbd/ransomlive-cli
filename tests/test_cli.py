import json
import ssl

import httpx
import pytest

from ransomlive import cli
from ransomlive.api import API_URL, AUTH_ENV_VAR, api_key, make_client

BASE = "https://api-pro.ransomware.live"
PAYLOAD = {"results": [{"id": "test", "website": "example.invalid", "extra": {"x": None}}]}


@pytest.mark.parametrize(
    ("argv", "url"),
    [
        (["validate"], "/validate"),
        (["stats"], "/stats"),
        (["sectors"], "/listsectors"),
        (["csirt", "fra"], "/csirt/FRA"),
        (
            ["8k", "--ticker", "msft", "--cik", "001", "--no-item801"],
            "/8k?ticker=MSFT&cik=001&item801=false",
        ),
        (["group", "test"], "/group/test"),
        (["groups"], "/groups"),
        (["groups", "a & b"], "/groups/a%20%26%20b"),
        (["iocs", "--type", "ip"], "/iocs?type=ip"),
        (["iocs", "test", "--type", "ip"], "/iocs/test?type=ip"),
        (["negotiations"], "/negotiations"),
        (["negotiations", "test"], "/negotiations/test"),
        (["negotiations", "test", "some #id"], "/negotiations/test/some%20%23id"),
        (["recent-press", "--country", "fr"], "/press/recent?country=FR"),
        (["press", "--year", "2024", "--month", "03"], "/press/all?year=2024&month=03"),
        (["ransomnotes"], "/ransomnotes"),
        (["ransomnotes", "test"], "/ransomnotes/test"),
        (["ransomnotes", "test", "one"], "/ransomnotes/test/one"),
        (["victim", "abc/z+="], "/victim/abc%2Fz%2B%3D"),
        (
            ["victims", "--group", "test", "--date", "attacked"],
            "/victims/?group=test&date=attacked",
        ),
        (["recent-victims", "--order", "attacked"], "/victims/recent?order=attacked"),
        (
            ["search", "a & b", "--sector", "Education", "--country", "us"],
            "/victims/search?q=a+%26+b&sector=Education&country=US",
        ),
        (["yara"], "/yara"),
        (["yara", "test"], "/yara/test"),
    ],
)
def test_routes_and_unmodified_json(argv, url, monkeypatch, capsys):
    seen = []

    def handle(request):
        seen.append((request.method, str(request.url), request.headers["X-API-KEY"]))
        return httpx.Response(200, json=PAYLOAD)

    real_make_client = make_client

    def client(key, *, verify=True):
        with real_make_client(key, verify=verify) as template:
            return httpx.Client(
                base_url=template.base_url,
                headers=template.headers,
                transport=httpx.MockTransport(handle),
            )

    monkeypatch.setenv(AUTH_ENV_VAR, "test-key")
    monkeypatch.setattr(cli, "make_client", client)
    assert cli.main(argv) == 0
    result = capsys.readouterr()
    assert result.err == ""
    assert json.loads(result.out) == {"source": "https://ransomware.live", "data": PAYLOAD}
    assert seen == [("GET", BASE + url, "test-key")]


@pytest.mark.parametrize(
    "argv",
    [
        ["victims"],
        ["victims", "--date", "attacked"],
        ["victims", "--year", "2025"],
        ["victims", "--month", "06"],
        ["press", "--year", "2024", "--month", "13"],
        ["press", "--month", "02"],
        ["recent-press", "--country", "FRA"],
        ["search", " "],
        ["groups", ".."],
        ["groups", "a/b"],
    ],
)
def test_bad_filters_fail_before_loading_credentials(argv, monkeypatch, capsys):
    def unexpected(*args):
        pytest.fail("invalid options should fail before authentication")

    monkeypatch.setattr(cli, "api_key", unexpected)
    with pytest.raises(SystemExit) as error:
        cli.main(argv)
    assert error.value.code == 2
    result = capsys.readouterr()
    assert not result.out
    assert "error:" in result.err


@pytest.mark.parametrize(
    ("status", "body", "headers", "code", "message"),
    [
        (302, b"", {"Location": "https://example.invalid"}, 1, "HTTP 302"),
        (401, b"private response", {}, 1, "HTTP 401"),
        (403, b"private response", {}, 1, "HTTP 403"),
        (404, b"private response", {}, 1, "HTTP 404"),
        (429, b"private response", {"Retry-After": "45"}, 3, "Wait at least 45 seconds"),
        (500, b"private response", {}, 1, "HTTP 500"),
        (200, b"private response", {}, 1, "valid JSON"),
    ],
)
def test_errors_never_print_response_body_or_follow_redirects(
    monkeypatch, capsys, status, body, headers, code, message
):
    calls = []

    def handle(request):
        calls.append(request)
        return httpx.Response(status, content=body, headers=headers)

    monkeypatch.setenv(AUTH_ENV_VAR, "test-key")
    monkeypatch.setattr(
        cli,
        "make_client",
        lambda key, *, verify: httpx.Client(
            base_url=API_URL, transport=httpx.MockTransport(handle)
        ),
    )
    assert cli.main(["stats"]) == code
    result = capsys.readouterr()
    assert len(calls) == 1
    assert not result.out
    assert message in result.err
    assert "private response" not in result.err


def test_env_priority_and_no_expansion(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_text(f'{AUTH_ENV_VAR}="example-${{SUFFIX}}"\n', encoding="utf-8-sig")
    monkeypatch.delenv(AUTH_ENV_VAR, raising=False)
    assert api_key(path) == "example-${SUFFIX}"
    monkeypatch.setenv(AUTH_ENV_VAR, "env-key")
    assert api_key(path) == "env-key"


def test_certificate_failure_is_reported_without_internal_details(monkeypatch, capsys):
    def handle(request):
        raise httpx.ConnectError("private transport details") from ssl.SSLCertVerificationError()

    monkeypatch.setenv(AUTH_ENV_VAR, "test-key")
    monkeypatch.setattr(
        cli,
        "make_client",
        lambda key, *, verify: httpx.Client(
            base_url=API_URL, transport=httpx.MockTransport(handle)
        ),
    )
    assert cli.main(["stats"]) == 1
    result = capsys.readouterr()
    assert not result.out
    assert "TLS certificate verification failed" in result.err
    assert "private transport details" not in result.err


@pytest.mark.parametrize(
    ("argv", "expected_verify", "warning"),
    [
        (["validate"], True, False),
        (["--insecure", "validate"], False, True),
        (["validate", "--insecure"], False, True),
        (["search-groups", "test", "--insecure"], False, True),
    ],
)
def test_insecure_is_explicit_and_warns_on_stderr(
    monkeypatch, capsys, argv, expected_verify, warning
):
    seen = []

    def client(key, *, verify):
        seen.append((key, verify))
        return httpx.Client(
            base_url=API_URL,
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json=[])),
        )

    monkeypatch.setenv(AUTH_ENV_VAR, "test-key")
    monkeypatch.setattr(cli, "make_client", client)
    assert cli.main(argv) == 0
    result = capsys.readouterr()
    assert seen == [("test-key", expected_verify)]
    assert ("WARNING" in result.err) is warning
    assert json.loads(result.out)["source"] == "https://ransomware.live"


def test_client_passes_verify_to_httpx(monkeypatch):
    options = []
    monkeypatch.setattr("ransomlive.api.httpx.Client", lambda **kwargs: options.append(kwargs))
    make_client("test-key")
    make_client("test-key", verify=False)
    assert [option["verify"] for option in options] == [True, False]
    assert all(not option["trust_env"] and not option["follow_redirects"] for option in options)


def test_certificate_failure_in_exception_context(monkeypatch, capsys):
    def handle(request):
        try:
            raise ssl.SSLCertVerificationError("private certificate details")
        except ssl.SSLCertVerificationError:
            raise httpx.ConnectError("private connection details") from None

    monkeypatch.setenv(AUTH_ENV_VAR, "test-key")
    monkeypatch.setattr(
        cli,
        "make_client",
        lambda key, *, verify: httpx.Client(
            base_url=API_URL, transport=httpx.MockTransport(handle)
        ),
    )
    assert cli.main(["stats"]) == 1
    result = capsys.readouterr()
    assert "TLS certificate verification failed" in result.err
    assert "private" not in result.err

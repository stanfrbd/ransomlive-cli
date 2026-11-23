import json

import httpx
import pytest

from ransomlive import cli
from ransomlive.api import API_URL, AUTH_ENV_VAR


@pytest.fixture
def mock_api(monkeypatch):
    def install(routes):
        requests = []

        def handle(request):
            assert str(request.url).startswith(API_URL + "/")
            requests.append(request)
            return httpx.Response(200, json=routes[request.url.path])

        monkeypatch.setenv(AUTH_ENV_VAR, "test-key")
        monkeypatch.setattr(
            cli,
            "make_client",
            lambda key, *, verify: httpx.Client(
                base_url=API_URL, transport=httpx.MockTransport(handle)
            ),
        )
        return requests

    return install


@pytest.mark.parametrize(
    ("mode", "query", "relations"),
    [
        ("exact", "login.example.co.uk", ["exact"]),
        ("include", "example.co.uk", ["exact", "parent", "subdomain", "same-root"]),
    ],
)
def test_domain_queries_and_link_fields(mock_api, capsys, mode, query, relations):
    candidates = [
        {"website": "example.co.uk"},
        {"website": "example.co.uk.unrelated.org"},
        {"website": "other.example.co.uk"},
        {
            "website": "LOGIN.example.co.uk.",
            "permalink": "https://ransomware.live/id/example",
            "claim_url": "https://leak.invalid/post",
        },
        {"website": "www.login.example.co.uk"},
        {"website": "notexample.co.uk"},
    ]
    requests = mock_api({"/victims/search": {"victims": candidates}})
    assert (
        cli.main(
            [
                "lookup-domain",
                "https://LOGIN.example.co.uk.:443/private?keep=local",
                "--match",
                mode,
                "--country",
                "fr",
            ]
        )
        == 0
    )
    assert dict(requests[0].url.params) == {"q": query, "country": "FR"}
    assert len(requests) == 1
    result = json.loads(capsys.readouterr().out)["data"]
    assert [row["match"] for row in result["matches"]] == relations
    assert result["matches"][0]["permalink"] == "https://ransomware.live/id/example"
    assert result["matches"][0]["post_url"] == "https://leak.invalid/post"


def test_include_does_not_broaden_to_private_suffix(mock_api, capsys):
    requests = mock_api({"/victims/search": [{"website": "unrelated.github.io"}]})
    assert cli.main(["lookup-domain", "sub.owner.github.io", "--match", "include"]) == 0
    assert requests[0].url.params["q"] == "owner.github.io"
    assert json.loads(capsys.readouterr().out)["data"]["matches"] == []


def test_organization_candidates_are_ranked_by_name_not_website(mock_api, capsys):
    requests = mock_api(
        {
            "/victims/search": [
                {"victim": "Example Heath", "screenshot": "https://images.invalid/test"},
                {"victim": "Another Company", "website": "example-health.invalid"},
                {"victim": "EXAMPLE-HEALTH"},
            ]
        }
    )
    assert cli.main(["lookup-name", "Example Health", "--candidate-query", "exam"]) == 0
    assert requests[0].url.params["q"] == "exam"
    matches = json.loads(capsys.readouterr().out)["data"]["matches"]
    assert [(row["victim"], row["match"]) for row in matches] == [
        ("EXAMPLE-HEALTH", "exact"),
        ("Example Heath", "close"),
    ]
    assert all(row["post_url"] is None for row in matches)


def test_group_alias_and_defanged_profile_round_trip(mock_api, monkeypatch, capsys, tmp_path):
    requests = mock_api(
        {
            "/groups": {"groups": [{"group": "test-group", "altname": "Former Name"}]},
            "/groups/test-group": {
                "locations": [
                    {"slug": "http://example.onion/", "fqdn": "example.onion", "available": True},
                    {"url": "https://notexample.onion"},
                ]
            },
        }
    )
    assert cli.main(["leak-sites", "former name"]) == 0
    assert [request.url.path for request in requests] == ["/groups", "/groups/test-group"]
    encoded = capsys.readouterr().out
    profile = json.loads(encoded)["data"]
    assert profile["group"] == "test-group"
    assert profile["locations"][0]["url"] == "hxxp://example[.]onion/"
    assert profile["locations"][0]["fqdn"] == "example[.]onion"
    path = tmp_path / "profile.json"
    path.write_text(encoded, encoding="utf-8")
    assert cli.main(["leak-sites", "test-group", "--no-defang"]) == 0
    assert "http://example.onion/" in capsys.readouterr().out

    def fail(*args):
        pytest.fail("reverse lookup must not load a key or create an API client")

    monkeypatch.setattr(cli, "api_key", fail)
    monkeypatch.setattr(cli, "make_client", fail)
    assert cli.main(["lookup-leak-site", "hxxps://example[.]onion/elsewhere", str(path)]) == 0
    result = json.loads(capsys.readouterr().out)["data"]
    assert result == {
        "hostname": "example[.]onion",
        "profiles_checked": 1,
        "matches": [{"group": "test-group", "url": "hxxp://example[.]onion/"}],
    }


def test_ambiguous_alias_does_not_request_a_profile(mock_api, capsys):
    requests = mock_api(
        {"/groups": [{"group": item, "altname": "Same Name"} for item in ("first", "second")]}
    )
    assert cli.main(["leak-sites", "Same Name"]) == 1
    result = capsys.readouterr()
    assert not result.out
    assert "ambiguous" in result.err
    assert len(requests) == 1


def test_search_groups_ranks_names_and_aliases_with_one_request(mock_api, capsys):
    requests = mock_api(
        {
            "/groups": [
                {"group": "lockbit3", "altname": None, "victims": 42},
                {"group": "different", "altname": "Former; LOCKBIT", "victims": 2},
                {"group": "lockbit", "altname": "", "victims": 3},
                {"group": "lockbt", "altname": ["other", "old name"], "victims": 1},
                {"group": "unrelated", "altname": None},
            ]
        }
    )
    assert cli.main(["search-groups", "LOCKBIT"]) == 0
    result = json.loads(capsys.readouterr().out)["data"]
    assert [request.url.path for request in requests] == ["/groups"]
    assert [(row["group"], row["match"], row["matched_name"]) for row in result["matches"]] == [
        ("different", "exact", "LOCKBIT"),
        ("lockbit", "exact", "lockbit"),
        ("lockbit3", "partial", "lockbit3"),
        ("lockbt", "close", "lockbt"),
    ]
    assert result["matches"][2]["victims"] == 42


def test_search_groups_partial_alias_and_empty_results(mock_api, capsys):
    mock_api({"/groups": {"groups": [{"group": "canonical", "altname": ["Former Name", "Other"]}]}})
    assert cli.main(["search-groups", "former", "--format", "markdown"]) == 0
    output = capsys.readouterr().out
    assert "canonical" in output and "Former Name" in output and "partial" in output
    assert cli.main(["search-groups", "xyz"]) == 0
    assert json.loads(capsys.readouterr().out)["data"]["matches"] == []


def test_search_groups_rejects_empty_query_before_request(mock_api, capsys):
    requests = mock_api({"/groups": []})
    with pytest.raises(SystemExit) as error:
        cli.main(["search-groups", "  "])
    assert error.value.code == 2
    assert "expected a name" in capsys.readouterr().err
    assert not requests


def test_reverse_search_reports_no_match_and_local_scope(capsys, tmp_path):
    profile = tmp_path / "profile.json"
    profile.write_text(
        json.dumps({"data": {"group": "test", "locations": ["https://notexample.onion"]}}),
        encoding="utf-8",
    )
    assert (
        cli.main(["lookup-leak-site", "example.onion", str(profile), "--format", "markdown"]) == 0
    )
    assert "matches (0 entries) across 1 local profiles" in capsys.readouterr().out


def test_invalid_lookup_host_fails_before_client(monkeypatch, capsys):
    def fail(*args):
        pytest.fail("invalid inputs must not create an API client")

    monkeypatch.setattr(cli, "make_client", fail)
    with pytest.raises(SystemExit) as error:
        cli.main(["lookup-domain", "https://user:password@example.org/"])
    assert error.value.code == 2
    stderr = capsys.readouterr().err
    assert "expected a hostname" in stderr
    assert "password" not in stderr

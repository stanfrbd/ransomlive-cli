import argparse
import json
import re
from difflib import SequenceMatcher
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx
import idna
from tldextract import TLDExtract

from ransomlive.api import APIError, JSONValue, get_json

_suffixes = TLDExtract(cache_dir=None, suffix_list_urls=(), include_psl_private_domains=True)


def _host(value: str) -> str:
    value = value.strip().replace("[.]", ".")
    value = re.sub(r"^hxxp(s?)://", r"http\1://", value, flags=re.IGNORECASE)
    if "\\" in value or any(char.isspace() or not char.isprintable() for char in value):
        raise ValueError("invalid hostname")
    parts = urlsplit(value if "://" in value else "//" + value)
    if (
        parts.scheme not in ("", "http", "https")
        or not parts.hostname
        or parts.username is not None
    ):
        raise ValueError("invalid hostname")
    raw = parts.hostname.removesuffix(".")
    try:
        return str(ip_address(raw))
    except ValueError:
        if "." not in raw:
            raise ValueError("expected a fully qualified hostname") from None
        return idna.encode(raw, uts46=True, std3_rules=True).decode("ascii")


def hostname(value: str) -> str:
    try:
        return _host(value)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a hostname or HTTP(S) URL") from None


def words(value: str) -> str:
    return " ".join(re.findall(r"[^\W_]+", value.casefold()))


def organization(value: str) -> str:
    if not words(value):
        raise argparse.ArgumentTypeError("expected a name with letters or digits")
    return value.strip()


def _records(data: JSONValue, collection: str) -> list[dict[str, JSONValue]]:
    if isinstance(data, dict):
        data = data.get(collection, data.get("results"))
    if not isinstance(data, list) or not all(isinstance(row, dict) for row in data):
        raise APIError(f"Unexpected API response: expected a list of {collection}.")
    return [row for row in data if isinstance(row, dict)]


def _text(row: dict[str, JSONValue], *keys: str) -> str | None:
    for key in keys:
        if isinstance(value := row.get(key), str) and value.strip():
            return value.strip()
    return None


def _victim(row: dict[str, JSONValue], match: str) -> dict[str, JSONValue]:
    return {
        "match": match,
        "victim": _text(row, "victim"),
        "group": _text(row, "group"),
        "website": _text(row, "website", "domain"),
        "discovered": _text(row, "discovered"),
        "permalink": _text(row, "permalink"),
        "post_url": _text(row, "claim_url", "post_url"),
        "id": _text(row, "id"),
    }


def _domain_lookup(
    client: httpx.Client, host: str, mode: str, filters: dict[str, str]
) -> JSONValue:
    root = _suffixes(host).top_domain_under_public_suffix
    keyword = root if mode == "include" and root else host
    rows = _records(get_json(client, "/victims/search", {"q": keyword, **filters}), "victims")
    matches = []
    for row in rows:
        website = _text(row, "website", "domain")
        if not website:
            continue
        try:
            candidate = _host(website)
        except ValueError:
            continue
        if candidate == host:
            match = "exact"
        elif (
            mode == "include"
            and root
            and _suffixes(candidate).top_domain_under_public_suffix == root
        ):
            if host.endswith("." + candidate):
                match = "parent"
            elif candidate.endswith("." + host):
                match = "subdomain"
            else:
                match = "same-root"
        else:
            continue
        matches.append(_victim(row, match))
    rank = {"exact": 0, "parent": 1, "subdomain": 2, "same-root": 3}
    matches.sort(key=lambda row: rank[str(row["match"])])
    return {"hostname": host, "match_mode": mode, "candidate_query": keyword, "matches": matches}


def _name_lookup(
    client: httpx.Client, name: str, keyword: str | None, filters: dict[str, str]
) -> JSONValue:
    normalized = words(name)
    keyword = keyword or max(normalized.split(), key=len)[:5]
    rows = _records(get_json(client, "/victims/search", {"q": keyword, **filters}), "victims")
    matches = []
    for row in rows:
        candidate = words(_text(row, "victim") or "")
        score = SequenceMatcher(None, normalized, candidate, autojunk=False).ratio()
        if candidate and (score >= 0.75 or f" {normalized} " in f" {candidate} "):
            matches.append((score, _victim(row, "exact" if candidate == normalized else "close")))
    matches.sort(key=lambda item: item[0], reverse=True)
    return {
        "organization": name,
        "candidate_query": keyword,
        "matches": [row for _, row in matches],
    }


def _aliases(row: dict[str, JSONValue]) -> list[str]:
    aliases = row.get("altname")
    if isinstance(aliases, str):
        aliases = [aliases, *re.split(r"[,;|]", aliases)]
    if not isinstance(aliases, list):
        return []
    return [alias.strip() for alias in aliases if isinstance(alias, str) and alias.strip()]


def _search_groups(client: httpx.Client, query: str) -> JSONValue:
    rows = _records(get_json(client, "/groups", {}), "groups")
    search = query.casefold()
    matches = []
    for row in rows:
        name = _text(row, "group")
        if not name:
            continue
        candidates = [name, *_aliases(row)]
        scored = []
        for candidate in candidates:
            normalized = candidate.casefold()
            score = SequenceMatcher(None, search, normalized, autojunk=False).ratio()
            if normalized == search:
                kind = "exact"
            elif search in normalized:
                kind = "partial"
            elif len(search) >= 4 and score >= 0.75:
                kind = "close"
            else:
                continue
            scored.append(({"exact": 0, "partial": 1, "close": 2}[kind], -score, candidate, kind))
        if scored:
            rank, score, matched_name, kind = min(scored)
            matches.append(
                (
                    rank,
                    score,
                    name.casefold(),
                    {
                        "group": name,
                        "altname": row.get("altname"),
                        "victims": row.get("victims"),
                        "match": kind,
                        "matched_name": matched_name,
                    },
                )
            )
    matches.sort(key=lambda item: item[:3])
    return {"query": query, "matches": [row for _, _, _, row in matches]}


def _group_name(client: httpx.Client, query: str) -> str:
    rows = _records(get_json(client, "/groups", {}), "groups")
    names = {name.casefold(): name for row in rows if (name := _text(row, "group"))}
    if query.casefold() in names:
        return names[query.casefold()]
    matches = set()
    for row in rows:
        if (name := _text(row, "group")) and any(
            alias.casefold() == query.casefold() for alias in _aliases(row)
        ):
            matches.add(name)
    if len(matches) > 1:
        raise APIError("Group alias is ambiguous; use a canonical name from `ransomlive groups`.")
    if not matches:
        raise APIError("No matching group name or alias.")
    return matches.pop()


def _profile(data: JSONValue, fallback: str | None = None) -> tuple[str, list[JSONValue]]:
    if isinstance(data, dict) and isinstance(data.get("group"), dict):
        data = data["group"]
    if isinstance(data, dict) and isinstance(locations := data.get("locations"), list):
        name = fallback or _text(data, "group", "name")
        if name:
            return name, locations
    raise APIError("Expected group profile data with a name and a locations list.")


def _location_url(location: JSONValue) -> str | None:
    values = (
        [_text(location, key) for key in ("url", "slug", "fqdn")]
        if isinstance(location, dict)
        else [location]
    )
    for value in values:
        if isinstance(value, str):
            try:
                _host(value)
            except ValueError:
                continue
            return value
    return None


def reverse_lookup(host: str, profiles: list[Path]) -> JSONValue:
    matches: list[JSONValue] = []
    seen = set()
    for path in profiles:
        try:
            document = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeError, ValueError):
            raise APIError(f"Could not read group profile: {str(path)!r}.", exit_code=2) from None
        try:
            name, locations = _profile(document.get("data") if isinstance(document, dict) else None)
        except APIError as error:
            raise APIError(f"{str(path)!r}: {error}", exit_code=2) from None
        for location in locations:
            url = _location_url(location)
            if not url:
                continue
            try:
                matches_host = _host(url) == host
            except ValueError:
                continue
            key = (name.casefold(), url)
            if matches_host and key not in seen:
                seen.add(key)
                matches.append({"group": name, "url": url})
    return {"hostname": host, "profiles_checked": len(profiles), "matches": matches}


def execute_lookup(client: httpx.Client, args: argparse.Namespace) -> JSONValue:
    if args.command == "search-groups":
        return _search_groups(client, args.query)
    if args.command == "leak-sites":
        name = _group_name(client, args.group)
        if name in {".", ".."} or any(char in "/\\" or not char.isprintable() for char in name):
            raise APIError("The API returned an invalid group identifier.")
        name, locations = _profile(get_json(client, "/groups/" + quote(name, safe=""), {}), name)
        sites: list[JSONValue] = []
        for location in locations:
            if url := _location_url(location):
                attributes = location if isinstance(location, dict) else {}
                sites.append({**attributes, "url": url})
        return {"group": name, "locations": sites}
    filters = {name: value for name in ("country", "group") if (value := getattr(args, name))}
    if args.command == "lookup-domain":
        return _domain_lookup(client, args.hostname, args.match, filters)
    return _name_lookup(client, args.organization, args.candidate_query, filters)

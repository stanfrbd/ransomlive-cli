# ransomlive-cli

A Python 3.11+ CLI for the [Ransomware.Live Pro REST API](https://api-pro.ransomware.live/docs).
Source: [Ransomware.Live](https://ransomware.live), created by [**Julien MOUSQUETON**](https://github.com/JMousqueton).
Victim listings are intelligence leads, not confirmation of incidents.

## Install

With [uv](https://docs.astral.sh/uv/), run without installing globally:

```sh
uvx --from git+https://github.com/stanfrbd/ransomlive-cli ransomlive --help
```

Or install the `ransomlive` command:

```sh
uv tool install git+https://github.com/stanfrbd/ransomlive-cli
# Or in an activated Python virtual environment:
pip install git+https://github.com/stanfrbd/ransomlive-cli
# From a local checkout:
pip install -e .
```

## Authentication

Get a personal Pro API key at [my.ransomware.live](https://my.ransomware.live/).
Set `RANSOMWARE_LIVE_TOKEN` in your environment or copy [.env.example](.env.example) to
`.env` in the directory where you run the CLI. The environment takes precedence.
`--env-file PATH` selects a different dotenv file. Keep the key out of Git and shell history.

```sh
ransomlive validate
ransomlive --help
ransomlive victims --help
```

The client sends `X-API-KEY` only to `https://api-pro.ransomware.live`, verifies TLS
by default, and does not use environment proxies or follow redirects. It never fetches artifacts,
screenshots, actor infrastructure, or other links returned in a response.
If a TLS-inspecting proxy prevents certificate verification, run from a network where
the Pro API's public certificate validates directly.

As an explicit, per-command last resort, `ransomlive --insecure validate` disables TLS
certificate verification and prints a warning to stderr. **This allows an attacker or
intermediary to impersonate the API and read or change your API key and data.** Do not
use it on untrusted networks. It does not configure a proxy or bypass network restrictions.

## Commands

| What you need | Command |
| --- | --- |
| Key status and statistics | `validate`, `stats` |
| Victim filters | `sectors`, `victims --country FR --year 2025 --month 06` |
| Victim search and recent activity | `search hospital --country US`, `recent-victims --order attacked` |
| One victim | `victim ID` (use an `id` from a listing) |
| Groups and profiles | `search-groups lock`, `groups`, `groups lockbit3` |
| Detection data | `iocs [GROUP] --type ip`, `yara [GROUP]` |
| Negotiations and ransom notes | `negotiations [GROUP [CHAT_ID]]`, `ransomnotes [GROUP [NOTE_NAME]]` |
| Press and SEC filings | `recent-press --country FR`, `press --year 2025`, `8k --year 2025 --no-item801` |
| CSIRT contacts | `csirt FR` or `csirt FRA` |

This covers the GET routes listed in the [Pro REST Swagger reference](https://api-pro.ransomware.live/swagger.json).
TAXII/STIX is a separate API and is not included.

## Analyst workflows

**Is this domain linked to a victim?** Paste a hostname or web URL. The CLI normalizes
the hostname and does not send the URL path, query, or fragment to the API.

```sh
ransomlive lookup-domain 'https://login.example.org/account' --match exact
ransomlive lookup-domain login.example.org --match include --country US --format json
```

`exact` (the default) matches only the normalized hostname. `include` searches the
registrable domain and labels exact, parent, subdomain, and same-root sibling matches.
It uses a bundled public suffix list (including private suffixes), without a network
fetch. Both modes filter the candidates returned by Pro substring search; no match
does not prove a domain was never listed. Use `--defang` to show the values as text.

**Find a victim by organization name.**

```sh
ransomlive lookup-name 'Example Health' --country US
ransomlive lookup-name 'Exampel Health' --candidate-query health --format json
```

Exact matches ignore case and punctuation. Close matches are ranked only among
candidates from a Pro substring query. By default the query uses the first five
characters of the longest word; change it with `--candidate-query` if needed.
Domain and name results show the Ransomware.live `permalink` and a separate `post_url`
when the API supplies an explicit claim or post link. A `null` link means unavailable;
the CLI does not guess. Use a returned `id` with `ransomlive victim ID --format json`
for the full victim record.

**Find a group's leak sites or check a known site.**

```sh
ransomlive search-groups lock
ransomlive leak-sites lockbit3 --format table
mkdir -p .ransomlive
ransomlive leak-sites lockbit3 --format json > .ransomlive/group.json
ransomlive lookup-leak-site 'hxxp://example[.]onion/path' .ransomlive/group.json
```

`search-groups` searches the group list by case-insensitive name or alias, including
partial names and close spelling matches (for queries of at least four characters).
Results are labeled `exact`, `partial`, or `close`, and show the canonical group name
and matched name. Close matches are suggestions, not confirmed identities. Use the
canonical group name from the results with `leak-sites`, which also recognizes exact
alternative names exposed by `/groups`.
Both leak-site commands defang by default; `--no-defang` displays the original values.
Reverse lookup compares exact hostnames in the supplied local profile files and
reports how many were checked. It does not use a key, call the API, or contact the
sites. Pass more files to broaden coverage. Keep the saved JSON private; `.ransomlive/`
is ignored by Git.

## Output

```sh
ransomlive recent-victims
ransomlive groups lockbit3 --format markdown --defang
ransomlive search hospital --format json --defang
```

- **Auto (default):** rich table on a terminal; JSON when redirected or piped.
- **Table and Markdown:** previews, with at most 100 rows and shortened long cells.
  Markdown escapes untrusted content; cells containing links use inline code to prevent
  automatic clickable links.
- **JSON:** one document on stdout, shaped as `{"source":"https://ransomware.live","data":...}`.
  REST commands return the complete API payload; analyst workflow commands return
  their selected matches or locations, without a display row limit.
- **`--defang`:** converts recognized URL schemes such as `https` to `hxxps` and dots in
  their hosts to `[.]`; it also defangs bare domains in recognized domain fields.
  This changes string values, not keys. Treat all API data as untrusted even when defanged.

Errors go to stderr. Exit status: `0` success, `1` request/output failure,
`2` usage or configuration error, `3` rate limit, `130` interrupted.

## Responsible use

Follow the [Ransomware.live terms](https://www.ransomware.live/t&c). Output is for local
analysis: do not publish raw data, re-serve it, or use it commercially without written
approval. Cite [Ransomware.live](https://ransomware.live) when using its intelligence.
The Pro API documents 60 requests per minute and 500,000 per month per key, with a
fair-use exception for IOC endpoints. Do not poll more often than the service's
30-minute cache interval. REST, group search, and victim lookup commands issue one request each;
`leak-sites` issues at most two and `lookup-leak-site` is offline. The CLI does not
retry on HTTP 429; respect any displayed `Retry-After` delay.

## Development

```sh
uv sync --locked --python 3.11
uv run pre-commit install
uv run pytest
uv run ransomlive --help
```

Push and pull request CI runs on Ubuntu, with Ruff and the shared Cyberbro pre-commit
configuration (including Bandit), offline HTTP mocks, and a wheel installation check.
With your own key, run the opt-in live smoke suite sparingly:

```sh
uv run python scripts/smoke_live.py
```

It attempts each documented GET route once, uses returned identifiers for dependent
checks, prints only pass/fail/skip labels, and stops on rate limiting. It is not run in CI.

A huge thank you to [**Julien MOUSQUETON**](https://github.com/JMousqueton) for developing Ransomware.Live for free.

The CLI code is [MIT licensed](LICENSE); that license does not apply to third-party API data.

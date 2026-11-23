import argparse
import re
from pathlib import Path
from urllib.parse import quote

from ransomlive.lookups import hostname, organization

FORMATS = ("auto", "table", "json", "markdown")
DATE_FIELDS = ("discovered", "attacked")


def _validate(pattern: str, message: str, value: str) -> str:
    if not re.fullmatch(pattern, value):
        raise argparse.ArgumentTypeError(message)
    return value


def _country(value: str) -> str:
    return _validate(r"[A-Za-z]{2}", "expected a two-letter ISO country code", value).upper()


def _csirt_country(value: str) -> str:
    return _validate(r"[A-Za-z]{2,3}", "expected a two- or three-letter ISO code", value).upper()


def _year(value: str) -> str:
    return _validate(r"[0-9]{4}", "expected a four-digit year", value)


def _month(value: str) -> str:
    return _validate(r"0[1-9]|1[0-2]", "expected a two-digit month (01-12)", value)


def _segment(value: str) -> str:
    if (
        not value.strip()
        or value in {".", ".."}
        or any(char in "/\\" or not char.isprintable() for char in value)
    ):
        raise argparse.ArgumentTypeError("expected a single non-empty identifier")
    return value


def _victim_id(value: str) -> str:
    return _validate(r"[a-zA-Z0-9+/_-]+={0,2}", "expected a Base64 victim ID", value)


def build_parser(version: str) -> argparse.ArgumentParser:
    shared = argparse.ArgumentParser(add_help=False, argument_default=argparse.SUPPRESS)
    shared.add_argument("--format", choices=FORMATS, help="auto: table on a TTY, otherwise JSON")
    shared.add_argument("--defang", action="store_true", help="defang URL and domain values")
    shared.add_argument("--env-file", type=Path, help="dotenv path (default: .env)")
    shared.add_argument(
        "--insecure",
        action="store_true",
        help="disable TLS certificate verification (exposes your API key to interception)",
    )

    parser = argparse.ArgumentParser(
        prog="ransomlive",
        description="Read-only Ransomware.live Pro REST threat intelligence.",
        parents=[shared],
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {version}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def command(
        name: str,
        path: str,
        help_text: str,
        query: tuple[str, ...] = (),
        segments: tuple[str, ...] = (),
    ) -> argparse.ArgumentParser:
        sub = commands.add_parser(name, parents=[shared], help=help_text, description=help_text)
        sub.set_defaults(path=path, query=query, segments=segments)
        return sub

    command("validate", "/validate", "Check API key status")
    command("stats", "/stats", "Show API statistics")
    command("sectors", "/listsectors", "List victim industry filters")
    command(
        "csirt", "/csirt", "Find CSIRT contacts by country", segments=("country",)
    ).add_argument("country", type=_csirt_country)
    command("group", "/group", "Show one group (singular route)", segments=("name",)).add_argument(
        "name", type=_segment
    )
    command(
        "groups", "/groups", "List groups or show one by name", segments=("group",)
    ).add_argument("group", nargs="?", type=_segment)
    command("victim", "/victim", "Show one victim by Base64 ID", segments=("id",)).add_argument(
        "id", type=_victim_id
    )
    command(
        "recent-victims", "/victims/recent", "List the 100 latest victims", ("order",)
    ).add_argument("--order", choices=DATE_FIELDS)

    filters = ("group", "sector", "country")
    victims = command(
        "victims",
        "/victims/",
        "List victims matching at least one filter",
        (*filters, "year", "month", "date"),
    )
    search = command(
        "search", "/victims/search", "Search victim names and websites", ("q", *filters, "order")
    )
    search.add_argument("q", help="case-insensitive substring")
    search.add_argument("--order", choices=DATE_FIELDS)
    for sub in (victims, search):
        sub.add_argument("--group", help="exact ransomware group")
        sub.add_argument("--sector", help="exact industry (see sectors)")
        sub.add_argument("--country", type=_country)
    victims.add_argument("--date", choices=DATE_FIELDS, help="which date to filter on")

    recent_press = command(
        "recent-press", "/press/recent", "List the 100 latest stories", ("country",)
    )
    press = command(
        "press", "/press/all", "List tracked press coverage", ("year", "month", "country")
    )
    for sub in (recent_press, press):
        sub.add_argument("--country", type=_country)

    filings = command(
        "8k",
        "/8k",
        "List SEC cybersecurity filings",
        ("ticker", "cik", "year", "month", "item105", "item801"),
    )
    filings.add_argument("--ticker", type=str.upper, help="stock ticker")
    filings.add_argument("--cik", help="SEC CIK (leading zeros are preserved)")
    for flag in ("item105", "item801"):
        filings.add_argument(f"--{flag}", action=argparse.BooleanOptionalAction, default=None)
    for sub in (victims, press, filings):
        sub.add_argument("--year", type=_year, help="four-digit year")
        sub.add_argument("--month", type=_month, help="two-digit month; requires --year")

    iocs = command(
        "iocs", "/iocs", "List IOC groups or a group's indicators", ("type",), ("group",)
    )
    iocs.add_argument("group", nargs="?", type=_segment)
    iocs.add_argument("--type", help="IOC type, e.g. ip, domain, sha256")
    for name, description, item in (
        ("yara", "List groups or retrieve a group's YARA rules", None),
        ("negotiations", "List negotiation groups, chats, or one transcript", "chat_id"),
        ("ransomnotes", "List ransom note groups, names, or one note", "note_name"),
    ):
        segments = ("group", item) if item else ("group",)
        sub = command(name, f"/{name}", description, segments=segments)
        sub.add_argument("group", nargs="?", type=_segment)
        if item:
            sub.add_argument(
                item, nargs="?", type=_segment, help="identifier returned by group listing"
            )

    def lookup(name: str, help_text: str) -> argparse.ArgumentParser:
        return commands.add_parser(name, parents=[shared], help=help_text, description=help_text)

    domain = lookup("lookup-domain", "Find victims by hostname or pasted web URL")
    domain.add_argument("hostname", type=hostname)
    domain.add_argument(
        "--match", choices=("exact", "include"), default="exact", help="default: exact hostname"
    )
    org = lookup("lookup-name", "Find exact and close victim name matches")
    org.add_argument("organization", type=organization)
    org.add_argument("--candidate-query", type=organization, help="override the API search term")
    group_search = lookup("search-groups", "Search group names and aliases")
    group_search.add_argument(
        "query", type=organization, help="full or partial group name or alias"
    )
    for sub in (domain, org):
        sub.add_argument("--country", type=_country)
        sub.add_argument("--group", type=_segment)
    sites = lookup("leak-sites", "Show a group's known leak sites by name or alias")
    sites.add_argument("group", type=_segment)
    reverse = lookup("lookup-leak-site", "Find a leak-site hostname in saved group profiles")
    reverse.add_argument("hostname", type=hostname)
    reverse.add_argument(
        "profiles", type=Path, nargs="+", help="local JSON profiles from leak-sites"
    )
    for sub in (sites, reverse):
        sub.add_argument(
            "--no-defang",
            action="store_false",
            dest="defang",
            default=argparse.SUPPRESS,
            help="show original URL values",
        )
    return parser


def request_for(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> tuple[str, dict[str, str]]:
    params = {}
    for key in args.query:
        value = getattr(args, key)
        if isinstance(value, bool):
            params[key] = "true" if value else "false"
        elif value is not None:
            if not value.strip():
                parser.error(f"{key} must not be empty")
            params[key] = value
    if "month" in params and "year" not in params:
        parser.error("--month requires --year")
    if args.command == "victims":
        if "year" in params and "month" not in params:
            parser.error("victims requires --month when --year is given")
        if not params.keys() & {"group", "sector", "country", "month"}:
            parser.error("victims requires --group, --sector, --country, or --year with --month")
    path = args.path
    for name in args.segments:
        value = getattr(args, name)
        if value is not None:
            path += "/" + quote(value, safe="")
    return path, params

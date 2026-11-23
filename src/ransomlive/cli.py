import sys
from importlib.metadata import version
from pathlib import Path

from ransomlive.api import APIError, api_key, get_json, make_client
from ransomlive.commands import build_parser, request_for
from ransomlive.lookups import execute_lookup, reverse_lookup
from ransomlive.output import render

_LEAK_SITE_COMMANDS = {"leak-sites", "lookup-leak-site"}
_ONLINE_LOOKUPS = {"lookup-domain", "lookup-name", "leak-sites", "search-groups"}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser(version("ransomlive-cli"))
    args = parser.parse_args(argv)
    try:
        if args.command == "lookup-leak-site":
            data = reverse_lookup(args.hostname, args.profiles)
        else:
            is_lookup = args.command in _ONLINE_LOOKUPS
            path, params = ("", {}) if is_lookup else request_for(parser, args)
            key = api_key(getattr(args, "env_file", Path(".env")))
            insecure = getattr(args, "insecure", False)
            if insecure:
                print(
                    "ransomlive: WARNING: TLS certificate verification is disabled; "
                    "your API key and data could be intercepted.",
                    file=sys.stderr,
                )
            with make_client(key, verify=not insecure) as client:
                data = execute_lookup(client, args) if is_lookup else get_json(client, path, params)
        render(
            data,
            sys.stdout,
            getattr(args, "format", "auto"),
            defanged=getattr(args, "defang", args.command in _LEAK_SITE_COMMANDS),
        )
    except APIError as error:
        print(f"ransomlive: {error}", file=sys.stderr)
        return error.exit_code
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 1
    return 0

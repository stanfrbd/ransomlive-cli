"""Opt-in live CLI checks. Only check labels and status are printed."""

import argparse
import io
import json
import re
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import TypeAlias

from ransomlive.api import JSONValue
from ransomlive.cli import main

Selector: TypeAlias = tuple[str, tuple[str, ...]]


def first_text(data: JSONValue, keys: tuple[str, ...]) -> str | None:
    if isinstance(data, dict):
        for key in keys:
            if isinstance(value := data.get(key), str) and value:
                return value
        values = [value for value in data.values() if isinstance(value, (dict, list))]
    elif isinstance(data, list):
        values = data
    elif isinstance(data, str):
        return data or None
    else:
        return None
    return next((found for value in values if (found := first_text(value, keys))), None)


def smoke(env_file: Path) -> int:
    results: dict[str, JSONValue] = {}
    failures = skips = 0

    def check(label: str, *argv: str | Selector) -> int:
        nonlocal failures, skips
        command = []
        for arg in argv:
            if isinstance(arg, str):
                command.append(arg)
                continue
            parent, keys = arg
            selected = first_text(results.get(parent), keys)
            if selected is None or selected.startswith("-"):
                print(f"SKIP {label}: no usable identifier from {parent}")
                skips += 1
                return 0
            command.append(selected)

        with redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
            try:
                code = main(["--env-file", str(env_file), "--format", "json", *command])
            except SystemExit as error:
                code = error.code
        if code:
            status = re.search(r"\bHTTP [345][0-9]{2}\b", stderr.getvalue())
            print(f"FAIL {label}: {status[0] if status else f'exit {code}'}")
            failures += 1
        else:
            results[label] = json.loads(stdout.getvalue())["data"]
            print(f"PASS {label}")
        return code if isinstance(code, int) else 1

    if check("validate", "validate"):
        return 1
    recent_id = ("recent victims", ("id",))
    negotiation_group = ("negotiation groups", ("group", "name"))
    negotiation_chat = ("negotiation chats", ("id", "chat_id"))
    note_group = ("note groups", ("group", "name"))
    note_name = ("note names", ("note_name", "name", "filename"))
    checks = [
        ("stats", "stats"),
        ("sectors", "sectors"),
        ("CSIRT", "csirt", "FR"),
        ("8-K", "8k", "--year", "2025", "--no-item801"),
        ("groups", "groups"),
        ("group (singular)", "group", "lockbit3"),
        ("group (plural)", "groups", "lockbit3"),
        ("IOC groups", "iocs", "--type", "ip"),
        ("group IOCs", "iocs", "lockbit3", "--type", "ip"),
        ("recent victims", "recent-victims"),
        ("victim", "victim", recent_id),
        ("filtered victims", "victims", "--country", "FR", "--year", "2025", "--month", "06"),
        ("victim search", "search", "hospital", "--country", "US"),
        ("recent press", "recent-press", "--country", "FR"),
        ("press", "press", "--year", "2025", "--month", "06"),
        ("YARA groups", "yara"),
        ("group YARA", "yara", ("YARA groups", ("group", "name"))),
        ("negotiation groups", "negotiations"),
        ("negotiation chats", "negotiations", negotiation_group),
        ("negotiation transcript", "negotiations", negotiation_group, negotiation_chat),
        ("note groups", "ransomnotes"),
        ("note names", "ransomnotes", note_group),
        ("note content", "ransomnotes", note_group, note_name),
    ]
    for label, *argv in checks:
        if check(label, *argv) == 3:
            print("Stopped on the first rate-limit response; no retries.")
            return 3
    print(f"{1 + len(checks) - failures - skips} passed, {failures} failed, {skips} skipped")
    return int(bool(failures or skips))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=Path(".env"))
    raise SystemExit(smoke(parser.parse_args().env_file))

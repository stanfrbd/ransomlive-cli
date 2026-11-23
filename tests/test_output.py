import io
import json

from markdown_it import MarkdownIt

from ransomlive.output import defang, render


def test_defang_nested_urls_without_altering_other_data():
    original = {
        "rule": "See https://example.invalid/path.txt, then call support.",
        "domains": ["bare.invalid", "www.test.invalid"],
        "other": 12,
    }
    assert defang(original) == {
        "rule": "See hxxps://example[.]invalid/path.txt, then call support.",
        "domains": ["bare[.]invalid", "www[.]test[.]invalid"],
        "other": 12,
    }
    assert original["domains"][0] == "bare.invalid"


def test_non_terminal_default_preserves_all_rows():
    data = [{"id": i, "value": "a" * 1000} for i in range(110)]
    output = io.StringIO()
    render(data, output, "auto")
    assert json.loads(output.getvalue())["data"] == data


def test_terminal_default_and_markdown_escape_untrusted_text():
    class Terminal(io.StringIO):
        def isatty(self):
            return True

    data = [{"group": "[red] \x1b]8;;evil <script>| *evil*"}]
    terminal = Terminal()
    render(data, terminal, "auto")
    assert "[red]" in terminal.getvalue()
    assert "\x1b]8;;evil" not in terminal.getvalue()
    assert "Source: Ransomware.live" in terminal.getvalue()

    markdown = io.StringIO()
    render(data, markdown, "markdown")
    assert "Source: [Ransomware.live](https://ransomware.live)" in markdown.getvalue()
    assert "<script>" not in markdown.getvalue()
    assert "&lt;script&gt;\\|" in markdown.getvalue()
    assert "*evil*" not in markdown.getvalue()


def test_markdown_is_compact_for_normal_values():
    output = io.StringIO()
    render(
        [{"country": "FR", "discovered": "2026-04-20T20:29:34.328509+00:00", "group": "test"}],
        output,
        "markdown",
    )
    text = output.getvalue()
    assert "| group | country | discovered |" in text
    assert "| test | FR | 2026-04-20T20:29:34.328509+00:00 |" in text
    assert "<code>" not in text
    assert "&#58;" not in text and "&#46;" not in text


def test_markdown_keeps_untrusted_content_as_text_and_in_one_cell():
    output = io.StringIO()
    payload = r"<script>alert(1)</script> | ![img](javascript:alert(1)) **bold** `code` \|"
    render([{"name": payload, "group": "test"}], output, "markdown")
    text = output.getvalue()
    html = MarkdownIt("commonmark").enable("table").render(text)
    assert "<script>" not in html and "<img" not in html and "<strong>" not in html
    assert "<code>" not in html
    assert html.count("<td>") == 2
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "![img](javascript:alert(1)) **bold** `code` \\|" in html


def test_markdown_neutralizes_automatic_links_and_unsafe_titles():
    output = io.StringIO()
    render(
        {
            "group": "# malicious <script>",
            "locations": [{"url": "https://evil.invalid/a|b", "title": "evil.com"}],
        },
        output,
        "markdown",
    )
    text = output.getvalue()
    html = MarkdownIt("commonmark").enable("table").render(text)
    assert "<h1>" not in html and "<script>" not in html
    assert '<a href="https://evil.invalid' not in html
    assert "<code>evil&#46;com</code>" in text

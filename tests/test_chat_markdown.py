"""
Tests for the chat Markdown renderer (static/md.js).

static/md.js is a UMD module: it exports via module.exports under Node and hangs
itself off the global object in a browser. So it can be exercised directly by
`node` - the same code path the console runs, not a re-implementation in Python.

Driven from Python via subprocess so it runs inside the existing unittest suite.
Every test skips (rather than fails) when node is missing, so the suite still
runs on a machine without it.

Run: cd soc-agent && MOCK_MODE=true ./venv/bin/python -m unittest tests.test_chat_markdown -v
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

BASE = Path(__file__).resolve().parent.parent
os.chdir(BASE)

MD_JS = BASE / "static" / "md.js"

NODE = shutil.which("node")

# One node process renders every case in the file. Spawning node per assertion
# costs ~40ms each and this file has 30+ of them.
_HARNESS = r"""
const md = require(process.argv[2]);
const cases = JSON.parse(process.argv[3]);
const out = cases.map(([src, mode]) =>
  mode === "text" ? md.toText(src) : mode === "inline" ? md.inline(src) : md.render(src)
);
process.stdout.write(JSON.stringify(out));
"""


def _render_all(cases: list[tuple[str, str]]) -> list[str]:
    """Run (source, mode) pairs through md.js and return the results."""
    if NODE is None:
        raise unittest.SkipTest("node is not installed")
    script = BASE / "tests" / "_md_harness.js"
    script.write_text(_HARNESS, encoding="utf-8")
    try:
        proc = subprocess.run(
            [NODE, str(script), str(MD_JS), json.dumps(cases)],
            capture_output=True,
            text=True,
            timeout=60,
        )
    finally:
        script.unlink(missing_ok=True)
    if proc.returncode != 0:
        raise AssertionError(f"node harness failed: {proc.stderr.strip()[:600]}")
    return json.loads(proc.stdout)


def render_all(sources: list[str]) -> list[str]:
    return _render_all([(s, "render") for s in sources])


def setUpModule():
    if NODE is None:
        raise unittest.SkipTest("node is not installed")
    if not MD_JS.is_file():
        raise unittest.SkipTest("static/md.js is missing")


class TestModuleShape(unittest.TestCase):
    def test_file_exists_and_is_umd(self):
        self.assertTrue(MD_JS.is_file())
        src = MD_JS.read_text(encoding="utf-8")
        self.assertIn("module.exports", src)
        self.assertIn("root.renderMarkdown", src)

    def test_exports_render_inline_totext(self):
        (r,) = _render_all([("x", "render")])
        self.assertIn("md-p", r)
        (i,) = _render_all([("**b**", "inline")])
        self.assertEqual(i, "<strong>b</strong>")
        (t,) = _render_all([("# Title\n\n- a\n- b", "text")])
        self.assertEqual(t, "Title a b")


class TestXSSHardening(unittest.TestCase):
    """This renders untrusted model output inside a security tool."""

    def test_script_tag_stays_text(self):
        (out,) = render_all(["<script>alert(1)</script>"])
        self.assertNotIn("<script>", out)
        self.assertIn("&lt;script&gt;", out)

    def test_img_onerror_stays_text(self):
        (out,) = render_all(['<img src=x onerror="alert(1)">'])
        self.assertNotIn("<img", out)
        self.assertIn("&lt;img", out)

    def test_raw_html_is_never_preserved(self):
        (out,) = render_all(["<b>bold</b> <i>it</i> <div>x</div>"])
        for tag in ("<b>", "<i>", "<div>"):
            self.assertNotIn(tag, out)

    def test_code_fence_escapes_its_contents(self):
        (out,) = render_all(["```html\n<script>alert(1)</script>\n```"])
        self.assertNotIn("<script>", out)
        self.assertIn("&lt;script&gt;", out)

    def test_javascript_scheme_is_refused(self):
        (out,) = render_all(["[click](javascript:alert(1))"])
        self.assertNotIn("javascript:", out)
        self.assertNotIn("<a ", out)

    def test_obfuscated_scheme_is_refused(self):
        """A control character inside the scheme must not smuggle it past."""
        for probe in ("java\tscript:alert(1)", "java\nscript:alert(1)", "  javascript:alert(1)"):
            (out,) = render_all([f"[x]({probe})"])
            self.assertNotIn("<a ", out, probe)

    def test_data_uri_is_refused(self):
        (out,) = render_all(["[x](data:text/html;base64,PHNjcmlwdD4=)"])
        self.assertNotIn("<a ", out)

    def test_attribute_injection_via_table_cell(self):
        (out,) = render_all(['| a |\n|---|\n| "><script>alert(1)</script> |'])
        self.assertNotIn("<script>", out)

    def test_attribute_injection_via_heading(self):
        (out,) = render_all(['# "><img src=x onerror=alert(1)>'])
        self.assertNotIn("<img", out)
        self.assertIn("&quot;", out)


class TestHrefPolicy(unittest.TestCase):
    """http/https/mailto leave; /path and #anchor stay; everything else is text."""

    def test_external_schemes_allowed(self):
        for url in ("https://wazuh.com/x", "http://example.org", "mailto:a@b.c"):
            (out,) = render_all([f"[t]({url})"])
            self.assertIn("<a href=", out, url)
            self.assertIn('target="_blank"', out, url)
            self.assertIn("noopener", out, url)

    def test_same_origin_path_allowed_and_stays_in_place(self):
        (out,) = render_all(["[Audit](/audit)"])
        self.assertIn('href="/audit"', out)
        # A new tab for an in-app link loses the session and looks broken.
        self.assertNotIn("target=", out)

    def test_fragment_allowed_and_stays_in_place(self):
        (out,) = render_all(["[Top](#alerts)"])
        self.assertIn('href="#alerts"', out)
        self.assertNotIn("target=", out)

    def test_protocol_relative_is_refused(self):
        """//host starts with "/" but resolves to another origin - the case a
        naive "allow anything starting with /" check walks straight into."""
        for url in ("//evil.example/x", "//evil.example"):
            (out,) = render_all([f"[evil]({url})"])
            self.assertNotIn("<a ", out, url)
            self.assertNotIn("evil.example", out, url)

    def test_bare_relative_is_refused(self):
        for url in ("audit", "../secrets", "./x"):
            (out,) = render_all([f"[t]({url})"])
            self.assertNotIn("<a ", out, url)

    def test_file_scheme_is_refused(self):
        (out,) = render_all(["[t](file:///etc/passwd)"])
        self.assertNotIn("<a ", out)

    def test_vbscript_is_refused(self):
        (out,) = render_all(["[t](vbscript:msgbox)"])
        self.assertNotIn("<a ", out)

    def test_label_survives_a_refused_href(self):
        """A refused link degrades to readable text, not to nothing."""
        (out,) = render_all(["[read the report](javascript:alert(1))"])
        self.assertIn("read the report", out)
        self.assertNotIn("<a ", out)

    def test_link_label_is_escaped(self):
        (out,) = render_all(["[<b>x</b>](https://a.example)"])
        self.assertNotIn("<b>", out)


class TestTables(unittest.TestCase):
    def test_gfm_table_renders_as_a_table(self):
        src = "| Severity | Count |\n|---|---|\n| high | 12 |\n| low | 3 |"
        (out,) = render_all([src])
        self.assertIn("<table", out)
        self.assertIn("md-th", out)
        self.assertIn("<tbody>", out)
        self.assertEqual(out.count("<tr"), 3)  # header + 2 body rows
        self.assertNotIn("|", out.replace("&#124;", ""))  # no literal pipes

    def test_alignment_row_is_consumed_not_rendered(self):
        (out,) = render_all(["| a | b |\n|:--|--:|\n| 1 | 2 |"])
        self.assertIn("text-align:right", out)
        self.assertNotIn("-:", out)

    def test_hyphens_in_data_cells_are_not_a_delimiter(self):
        """'half-configured' and rule names contain hyphens; a naive check
        treats the row as a delimiter and drops the data."""
        (out,) = render_all(["| a |\n|---|\n| half-configured |"])
        self.assertIn("half-configured", out)

    def test_escaped_pipe_in_a_cell(self):
        (out,) = render_all(["| a |\n|---|\n| x \\| y |"])
        self.assertIn("x | y", out)

    def test_short_rows_are_padded_not_crashed(self):
        (out,) = render_all(["| a | b |\n|---|---|\n| 1 |"])
        self.assertIn("<td", out)

    def test_severity_cell_gets_a_badge(self):
        (out,) = render_all(["| Severity |\n|---|\n| **critical** |"])
        self.assertIn('class="sev critical"', out)
        self.assertIn("<strong>critical</strong>", out)

    def test_numeric_cell_gets_mono(self):
        (out,) = render_all(["| Count |\n|---|\n| 1,204 |"])
        self.assertIn('class="num"', out)


class TestBlocks(unittest.TestCase):
    def test_fenced_code(self):
        (out,) = render_all(["```bash\nwazuh-control status\n```"])
        self.assertIn("<pre", out)
        self.assertIn("lang-bash", out)
        self.assertIn("wazuh-control status", out)

    def test_unclosed_fence_still_closes(self):
        (out,) = render_all(["```\nnever closed"])
        self.assertIn("</code></pre>", out)
        self.assertIn("never closed", out)

    def test_headings(self):
        (out,) = render_all(["## Scope"])
        self.assertIn("md-h2", out)
        self.assertIn("Scope", out)

    def test_blockquote(self):
        (out,) = render_all(["> quoted line"])
        self.assertIn("md-quote", out)
        self.assertIn("quoted line", out)

    def test_thematic_break(self):
        (out,) = render_all(["---"])
        self.assertIn("md-hr", out)

    def test_horizontal_rule_is_not_a_list(self):
        (out,) = render_all(["- - -"])
        self.assertIn("md-hr", out)

    def test_nested_list(self):
        (out,) = render_all(["- outer\n  - inner"])
        self.assertIn("<ul", out)
        # The inner list must live inside the parent <li>, not beside it.
        self.assertLess(out.index("outer"), out.index("inner"))
        self.assertEqual(out.count("<ul"), 2)

    def test_ordered_list(self):
        (out,) = render_all(["1. first\n2. second"])
        self.assertIn("<ol", out)
        self.assertEqual(out.count("<li"), 2)

    def test_lazy_continuation(self):
        (out,) = render_all(["- a long item\n  that wraps"])
        self.assertIn("that wraps", out)
        self.assertIn("a long item", out)

    def test_inline_code_is_not_parsed_as_markdown(self):
        (out,) = render_all(["`**not bold**`"])
        self.assertIn("<code>", out)
        self.assertNotIn("<strong>", out)

    def test_underscores_in_a_word_are_not_emphasis(self):
        """rule_groups must survive; a bare _.._ rule would eat it."""
        (out,) = render_all(["rule_groups and data_srcip"])
        self.assertIn("rule_groups", out)
        self.assertNotIn("<em>", out)

    def test_strikethrough(self):
        (out,) = render_all(["~~old~~"])
        self.assertIn("<del>", out)

    def test_paragraph_newlines_become_a_single_block(self):
        (out,) = render_all(["one\ntwo\nthree"])
        self.assertEqual(out.count("<p"), 1)


class TestToText(unittest.TestCase):
    """toText flattens Markdown to one plain line. It is exported for callers
    that want a preview string; the console itself renders HTML, so nothing in
    templates/index.html calls it. It strips syntax markers, NOT table cell
    separators - the data rows keep their pipes. Asserted here so the contract
    is written down rather than assumed."""

    def test_strips_structure_for_a_single_line(self):
        (out,) = _render_all([("# Title\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n- x", "text")])
        self.assertNotIn("#", out)
        self.assertNotIn("**", out)
        self.assertNotIn("\n", out)
        self.assertNotIn("---", out)
        # Cell separators survive - this is not a table flattener.
        self.assertIn("|", out)
        self.assertIn("Title", out)
        self.assertIn("x", out)

    def test_keeps_link_label(self):
        (out,) = _render_all([("[read this](https://a.example)", "text")])
        self.assertEqual(out, "read this")

    def test_handles_null_and_undefined(self):
        (out,) = _render_all([("null", "text")])
        self.assertIsInstance(out, str)


class TestTemplateWiring(unittest.TestCase):
    """The renderer is only useful if the console actually calls it."""

    @classmethod
    def setUpClass(cls):
        cls.html = (BASE / "templates" / "index.html").read_text(encoding="utf-8")

    def test_script_is_loaded_before_the_inline_script(self):
        self.assertIn("url_for('static', filename='md.js')", self.html)
        tag = self.html.index("url_for('static', filename='md.js')")
        main = self.html.index('<script>\n"use strict";')
        self.assertLess(tag, main, "md.js must load before the code that calls it")

    def test_chat_uses_markdown_not_esc(self):
        fn = self.html.split("function renderChatMessages()")[1].split("\nasync function")[0]
        self.assertIn("mdish(", fn)
        self.assertNotIn("esc(m.content)", fn)

    def test_mdish_falls_back_safely(self):
        """If md.js 404s the console must still be safe, just plainer."""
        fn = self.html.split("function mdish(text)")[1].split("\n}")[0]
        self.assertIn("typeof renderMarkdown", fn)
        self.assertIn("esc(s)", fn)

    def test_only_one_esc_definition_exists(self):
        """Two `esc` declarations meant the weaker one (no quote escaping) won
        for the whole script, because the later hoisted declaration shadows the
        earlier one."""
        import re

        defs = re.findall(r"^function esc\(", self.html, re.M)
        self.assertEqual(len(defs), 1, "duplicate esc() definitions - the later one silently wins")

    def test_the_remaining_esc_escapes_quotes(self):
        m = (
            re.search(r"^function esc\((.*?)\n", self.html, re.M)
            if (re := __import__("re"))
            else None
        )
        self.assertIsNotNone(m)
        self.assertIn('"', m.group(0))

    def test_pre_wrap_is_reset_for_rendered_markdown(self):
        """pre-wrap on top of rendered block elements adds a phantom newline
        per source line, which shreds table rows."""
        self.assertIn(".chat-msg .md-p,", self.html)
        self.assertIn("white-space: normal;", self.html)

    def test_markdown_classes_are_styled(self):
        for cls in ("md-table", "md-th", "md-pre", "md-quote", "md-list", "md-hr", "sev"):
            self.assertIn(f".chat-msg .{cls}", self.html, cls)

    def test_static_asset_is_ungated_exactly(self):
        """A <script src> cannot send an Authorization header, so md.js has to
        be reachable - but as an exact path, not a blanket /static/ prefix."""
        src = (BASE / "dashboard.py").read_text(encoding="utf-8")
        self.assertIn("_UNGATED_ASSETS", src)
        self.assertIn('"/static/md.js"', src)
        block = src.split("_UNGATED_ASSETS = frozenset(")[1].split(")")[0]
        self.assertNotIn("startswith", block, "must not exempt all of /static/")


class TestAuthGate(unittest.TestCase):
    def test_md_js_is_reachable_with_auth_on(self):
        import dashboard

        dashboard.app.config["TESTING"] = True
        c = dashboard.app.test_client()
        r = c.get("/static/md.js")
        self.assertEqual(r.status_code, 200)
        self.assertIn("javascript", r.get_data(as_text=True).lower())

    def test_gate_still_blocks_other_static_paths(self):
        """The exemption is exact, so anything else under /static/ stays gated."""
        import dashboard

        self.assertEqual(dashboard._UNGATED_ASSETS, frozenset({"/static/md.js"}))

    def test_api_stays_gated(self):
        import dashboard

        self.assertNotIn("/api/health", dashboard._UNGATED_ASSETS)


if __name__ == "__main__":
    unittest.main()

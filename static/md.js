/* renderMarkdown - a small, dependency-free Markdown renderer for the SOC console.
 *
 * WHY THIS FILE EXISTS
 * The analyst replies in Markdown (headings, GFM pipe tables, nested bullet
 * lists, fenced code). The console used to render replies through esc(), so a
 * table arrived on screen as literal pipe-soup with visible "**" markers. This
 * renders the subset of Markdown the analyst actually emits, styled by the
 * console's own design tokens.
 *
 * SECURITY
 * This renders untrusted model output inside a security tool, so it is
 * escape-first and allow-list by construction:
 *   - every character of input is HTML-escaped before any tag is constructed;
 *   - the only tags in the output are the ones this file builds;
 *   - raw HTML in a reply can never pass through, so <script> stays text;
 *   - link targets are restricted to http/https/mailto, with control
 *     characters and whitespace stripped first so "java\nscript:" cannot
 *     smuggle a scheme past the check.
 *
 * Runs in the browser (window.renderMarkdown) and in node (module.exports) so
 * the same code path is covered by tests/test_chat_markdown.py.
 */
(function (root, factory) {
  "use strict";
  var api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.MarkdownConsole = api;
    root.renderMarkdown = api.render;
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  /* ----------------------------------------------------------------- utils */

  function escapeHtml(s) {
    return String(s === undefined || s === null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  /* Classify an href target: "external", "internal", or null (refuse).
   *
   * Allowed:
   *   external - http:, https:, mailto:            (leaves the console)
   *   internal - "/audit", "/api/proposals"        (same origin, in place)
   *               "#some-anchor"                    (same page, in place)
   *
   * Refused, and the first entry is the one that matters:
   *   "//evil.example" - protocol-relative. It starts with "/" and looks like a
   *     path, but a browser resolves it against the current scheme and lands on
   *     a DIFFERENT host. Letting it through the "/" branch would turn a
   *     same-origin-looking link into an off-site one, so it is rejected
   *     explicitly instead of being treated as internal.
   *   "javascript:", "data:", "vbscript:", "file:" - and bare relative paths
   *     like "audit" or "../secrets", which nothing the analyst emits needs and
   *     each of which widens the blast radius of a crafted reply.
   *
   * The probe strips control characters and whitespace first: browsers ignore
   * them inside a URL, so "jav&#9;ascript:" style obfuscation has to be
   * normalised before the scheme test can see it. */
  function hrefKind(raw) {
    var url = String(raw === undefined || raw === null ? "" : raw).trim();
    if (!url) return null;
    var probe = url.replace(/[\u0000-\u0020\u007f]/g, "").toLowerCase();
    if (!probe) return null;
    if (probe.slice(0, 2) === "//") return null;
    if (/^(https?:|mailto:)/.test(probe)) return "external";
    if (probe.charAt(0) === "#") return "internal";
    if (probe.charAt(0) === "/") return "internal";
    return null;
  }

  function safeHref(raw) {
    if (!hrefKind(raw)) return null;
    return escapeHtml(String(raw).trim());
  }

  var SEVERITY = {
    critical: "critical",
    crit: "critical",
    high: "high",
    medium: "medium",
    med: "medium",
    moderate: "medium",
    low: "low",
    info: "info",
    informational: "info"
  };

  /* Strip inline markers so we can read a cell's actual value. */
  function plainText(cell) {
    return String(cell)
      .replace(/\*\*|__|~~|`/g, "")
      .replace(/\s+/g, " ")
      .trim()
      .toLowerCase();
  }

  function decorateCell(text) {
    var sev = SEVERITY[plainText(text)];
    if (sev) {
      return '<span class="sev ' + sev + '">' + escapeHtml(text).replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>") + "</span>";
    }
    /* Purely numeric cells get the console's tabular mono treatment. */
    if (/^[-+]?[$£€]?\d[\d,._ ]*[%a-z]?$/i.test(String(text).trim())) {
      return '<span class="num">' + escapeHtml(text) + "</span>";
    }
    return inline(text);
  }

  /* ---------------------------------------------------------------- inline */

  function inline(text) {
    if (text === undefined || text === null) return "";

    /* Code spans are lifted out first so their contents are never treated as
     * emphasis or a link, then restored last. */
    var codes = [];
    var s = String(text).replace(/`([^`]+)`/g, function (_m, code) {
      codes.push(code);
      return "\u0000C" + (codes.length - 1) + "\u0000";
    });

    s = escapeHtml(s);

    /* Links before emphasis: an underscore or asterisk inside a URL must not
     * be eaten by the emphasis rules below. */
    s = s.replace(/\[([^\]]*)\]\(\s*([^)\s]+)(?:\s+&quot;[^&]*&quot;)?\s*\)/g, function (m, label, href) {
      var kind = hrefKind(href);
      var safe = safeHref(href);
      /* A refused href degrades to plain text, never to a dead or unsafe link. */
      if (!kind || !safe) return escapeHtml(label);
      /* Only a link that leaves the console opens in a new tab. A same-origin
       * "/audit" or "#anchor" target must navigate in place - forcing a new tab
       * for an in-app link loses the session and looks broken. */
      if (kind === "external") {
        return '<a href="' + safe + '" target="_blank" rel="noopener noreferrer">' + label + "</a>";
      }
      return '<a href="' + safe + '">' + label + "</a>";
    });

    s = s.replace(/\*\*\*([^*]+)\*\*\*/g, "<strong><em>$1</em></strong>");
    s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    s = s.replace(/(^|[\s(>])\*([^*\n]+)\*(?=[\s).,!?:;]|$)/g, "$1<em>$2</em>");
    s = s.replace(/__([^_]+)__/g, "<strong>$1</strong>");
    s = s.replace(/(^|[\s(>])_([^_\n]+)_(?=[\s).,!?:;]|$)/g, "$1<em>$2</em>");
    s = s.replace(/~~([^~]+)~~/g, "<del>$1</del>");

    /* Backslash escapes: unescape last, only for punctuation Markdown escapes. */
    s = s.replace(/\\([\\`*_{}\[\]()#+\-.!~>|])/g, "$1");

    s = s.replace(/\u0000C(\d+)\u0000/g, function (_m, n) {
      return "<code>" + escapeHtml(codes[Number(n)]) + "</code>";
    });

    /* A trailing backslash or two trailing spaces is a hard break. */
    s = s.replace(/(?: {2,}|\\)\n/g, "<br>\n");

    return s;
  }

  /* ---------------------------------------------------------------- tables */

  function splitRow(line) {
    var s = String(line).trim();
    if (s.charAt(0) === "|") s = s.slice(1);
    if (s.charAt(s.length - 1) === "|") s = s.slice(0, -1);

    var cells = [];
    var cur = "";
    for (var i = 0; i < s.length; i++) {
      var ch = s.charAt(i);
      if (ch === "\\" && s.charAt(i + 1) === "|") {
        cur += "|";
        i++;
      } else if (ch === "|") {
        cells.push(cur);
        cur = "";
      } else {
        cur += ch;
      }
    }
    cells.push(cur);
    return cells.map(function (c) {
      return c.trim();
    });
  }

  function isTableRow(line) {
    return typeof line === "string" && line.indexOf("|") !== -1 && line.trim() !== "";
  }

  function isDelimiterRow(line) {
    if (!isTableRow(line)) return false;
    return /^\|?\s*:?-{1,}:?\s*(\|\s*:?-{1,}:?\s*)*\|?$/.test(String(line).trim());
  }

  function alignments(delims) {
    return delims.map(function (d) {
      var left = d.charAt(0) === ":";
      var right = d.charAt(d.length - 1) === ":";
      if (left && right) return "center";
      if (right) return "right";
      return "left";
    });
  }

  function renderTable(header, aligns, rows) {
    var html = '<div class="md-tablewrap"><table class="md-table"><thead><tr>';
    for (var h = 0; h < header.length; h++) {
      var ha = aligns[h] || "left";
      html += '<th class="md-th" style="text-align:' + ha + '">' + inline(header[h]) + "</th>";
    }
    html += "</tr></thead><tbody>";

    for (var r = 0; r < rows.length; r++) {
      var cells = rows[r];
      html += "<tr>";
      for (var c = 0; c < header.length; c++) {
        var a = aligns[c] || "left";
        html += '<td style="text-align:' + a + '">' + decorateCell(cells[c] === undefined ? "" : cells[c]) + "</td>";
      }
      html += "</tr>";
    }
    return html + "</tbody></table></div>";
  }

  /* ----------------------------------------------------------------- lists */

  var BULLET = /^(\s*)([-*+])(\s+)(.*)$/;
  var ORDERED = /^(\s*)(\d{1,9})([.)])(\s+)(.*)$/;

  function listItem(line) {
    var b = BULLET.exec(line);
    if (b) return { indent: b[1].replace(/\t/g, "  ").length, type: "ul", text: b[4] };
    var o = ORDERED.exec(line);
    if (o) return { indent: o[1].replace(/\t/g, "  ").length, type: "ol", text: o[5] };
    return null;
  }

  /* Flat items -> tree, so a nested list is emitted *inside* its parent <li>
   * rather than as a sibling list. */
  function toTree(items) {
    var root = [];
    var stack = [];
    for (var i = 0; i < items.length; i++) {
      var it = items[i];
      while (stack.length && it.indent <= stack[stack.length - 1].indent) stack.pop();
      var node = { text: it.text, type: it.type, indent: it.indent, children: [] };
      if (stack.length) stack[stack.length - 1].node.children.push(node);
      else root.push(node);
      stack.push({ indent: it.indent, node: node });
    }
    return root;
  }

  /* Render a level of the tree, grouping consecutive siblings that share a
   * marker type into one <ul>/<ol>. */
  function renderNodes(nodes) {
    var out = "";
    var i = 0;
    while (i < nodes.length) {
      var type = nodes[i].type;
      var group = [nodes[i]];
      var j = i + 1;
      while (j < nodes.length && nodes[j].type === type) {
        group.push(nodes[j]);
        j++;
      }
      out += "<" + type + ' class="md-list">';
      for (var k = 0; k < group.length; k++) {
        var n = group[k];
        out += "<li>" + inline(n.text) + (n.children.length ? renderNodes(n.children) : "") + "</li>";
      }
      out += "</" + type + ">";
      i = j;
    }
    return out;
  }

  /* ----------------------------------------------------------------- block */

  function isBlockStart(line, next) {
    if (line === undefined) return false;
    if (!line.trim()) return true;
    if (/^\s{0,3}(`{3,}|~{3,})/.test(line)) return true;
    if (/^\s{0,3}#{1,6}\s+/.test(line)) return true;
    if (/^\s{0,3}>/.test(line)) return true;
    if (/^\s{0,3}([-*_])[ \t]*(?:\1[ \t]*){2,}$/.test(line)) return true;
    if (listItem(line)) return true;
    if (isTableRow(line) && isDelimiterRow(next)) return true;
    return false;
  }

  function render(text) {
    if (text === undefined || text === null) return "";

    var lines = String(text).replace(/\r\n?/g, "\n").split("\n");
    var out = "";
    var i = 0;

    while (i < lines.length) {
      var line = lines[i];

      if (!line.trim()) {
        i++;
        continue;
      }

      /* ---- fenced code -------------------------------------------------- */
      var fence = /^\s{0,3}(`{3,}|~{3,})\s*([A-Za-z0-9_+-]*)\s*$/.exec(line);
      if (fence) {
        var marker = fence[1].charAt(0);
        var len = fence[1].length;
        var body = [];
        i++;
        while (i < lines.length) {
          var closer = new RegExp("^\\s{0,3}" + (marker === "`" ? "`" : "~") + "{" + len + ",}\\s*$");
          if (closer.test(lines[i])) {
            i++;
            break;
          }
          body.push(lines[i]);
          i++;
        }
        out +=
          '<pre class="md-pre"><code class="md-code' +
          (fence[2] ? " lang-" + escapeHtml(fence[2]) : "") +
          '">' +
          escapeHtml(body.join("\n")) +
          "</code></pre>";
        continue;
      }

      /* ---- thematic break ----------------------------------------------- */
      if (/^\s{0,3}([-*_])[ \t]*(?:\1[ \t]*){2,}$/.test(line)) {
        out += '<hr class="md-hr">';
        i++;
        continue;
      }

      /* ---- heading ------------------------------------------------------ */
      var head = /^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$/.exec(line);
      if (head) {
        var level = head[1].length;
        out +=
          '<h' + level + ' class="md-h md-h' + level + '">' + inline(head[2]) + "</h" + level + ">";
        i++;
        continue;
      }

      /* ---- table -------------------------------------------------------- */
      if (isTableRow(line) && isDelimiterRow(lines[i + 1])) {
        var header = splitRow(line);
        var aligns = alignments(splitRow(lines[i + 1]));
        i += 2;
        var rows = [];
        /* The header and delimiter are already consumed, so every following
         * pipe row is data. Do not test for "-" here: data cells legitimately
         * contain hyphens ("half-configured", dates, rule names). */
        while (i < lines.length && isTableRow(lines[i])) {
          rows.push(splitRow(lines[i]));
          i++;
        }
        out += renderTable(header, aligns, rows);
        continue;
      }

      /* ---- blockquote --------------------------------------------------- */
      if (/^\s{0,3}>/.test(line)) {
        var quoted = [];
        while (i < lines.length && (/^\s{0,3}>/.test(lines[i]) || (lines[i].trim() && quoted.length))) {
          quoted.push(lines[i].replace(/^\s{0,3}>\s?/, ""));
          i++;
        }
        out += '<blockquote class="md-quote">' + render(quoted.join("\n")) + "</blockquote>";
        continue;
      }

      /* ---- list --------------------------------------------------------- */
      if (listItem(line)) {
        var items = [];
        while (i < lines.length) {
          var li = listItem(lines[i]);
          if (li) {
            items.push(li);
            i++;
          } else if (lines[i].trim() && lines[i].search(/\S/) >= (items[items.length - 1].indent + 2)) {
            /* Lazy continuation of the previous item. */
            items[items.length - 1].text += " " + lines[i].trim();
            i++;
          } else {
            break;
          }
        }
        out += renderNodes(toTree(items));
        continue;
      }

      /* ---- paragraph ---------------------------------------------------- */
      var para = [line];
      i++;
      while (i < lines.length && !isBlockStart(lines[i], lines[i + 1])) {
        para.push(lines[i]);
        i++;
      }
      out += '<p class="md-p">' + inline(para.join("\n")) + "</p>";
    }

    return out;
  }

  /* Strip markdown down to readable text - used for chat previews, titles and
   * anything that needs a single line rather than HTML. */
  function toText(text) {
    return String(text === undefined || text === null ? "" : text)
      .replace(/```[\s\S]*?```/g, " ")
      .replace(/^\s{0,3}#{1,6}\s+/gm, "")
      .replace(/^\s{0,3}>\s?/gm, "")
      .replace(/^\s*[-*+]\s+/gm, "")
      .replace(/^\s*\d{1,9}[.)]\s+/gm, "")
      .replace(/^\s*\|?[\s:|-]*\|[\s:|-]*$/gm, " ")
      .replace(/[*_`~]/g, "")
      .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
      .replace(/\s+/g, " ")
      .trim();
  }

  return { render: render, inline: inline, toText: toText, escapeHtml: escapeHtml };
});

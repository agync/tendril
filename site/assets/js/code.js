// The language tabs on the code sample: arrow keys move between tabs, the choice is remembered,
// a small highlighter colours strings, comments, numbers and keywords, and Copy copies the
// install line. All panels share one grid cell, so the card keeps the tallest panel's height and
// does not jump between tabs. Without script every language shows, one after another.
(function () {
  var KEY = "tendril-lang";
  var KEYWORDS = {
    python: "import|from|def|return|True|False|None|lambda",
    typescript: "import|from|const|let|new|await|return|true|false",
    go: "import|if|err|nil|return|func|var",
    swift: "import|let|var|try|as|return|true|false",
    kotlin: "import|val|var|return|true|false",
    rust: "let|mut|use|fn|async|await|else|Some|None|Ok|Err|move",
    cli: "tendril",
  };
  var COMMENT = { python: "#", cli: "#" };

  function escape(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function highlight(code, lang) {
    var text = code.textContent;
    var hash = COMMENT[lang] === "#";
    var words = KEYWORDS[lang] || "";
    var parts = [
      hash ? "#[^\\n]*" : "\\/\\/[^\\n]*",
      '"(?:[^"\\\\\\n]|\\\\.)*"',
      "\\b\\d+\\b",
      words ? "\\b(?:" + words + ")\\b" : null,
    ].filter(Boolean);
    var re = new RegExp(parts.join("|"), "g");
    var out = "";
    var last = 0;
    text.replace(re, function (m, offset) {
      out += escape(text.slice(last, offset));
      var cls = m[0] === "#" || m.slice(0, 2) === "//" ? "c-c" : m[0] === '"' ? "c-s" : /^\d/.test(m) ? "c-n" : "c-k";
      out += '<span class="' + cls + '">' + escape(m) + "</span>";
      last = offset + m.length;
      return m;
    });
    code.innerHTML = out + escape(text.slice(last));
  }

  document.querySelectorAll("[data-tabs]").forEach(function (box) {
    var tabs = Array.prototype.slice.call(box.querySelectorAll('[role="tab"]'));
    var panels = box.querySelectorAll('[role="tabpanel"]');
    box.classList.add("is-tabbed");
    panels.forEach(function (p) {
      p.querySelectorAll("pre code").forEach(function (code) {
        highlight(code, p.dataset.lang);
      });
    });

    function select(lang, focus) {
      tabs.forEach(function (t) {
        var on = t.dataset.lang === lang;
        t.setAttribute("aria-selected", on ? "true" : "false");
        t.tabIndex = on ? 0 : -1;
        if (on && focus) t.focus();
      });
      panels.forEach(function (p) {
        var off = p.dataset.lang !== lang;
        p.inert = off;
        p.setAttribute("aria-hidden", off ? "true" : "false");
      });
    }

    tabs.forEach(function (t, i) {
      t.addEventListener("click", function () {
        select(t.dataset.lang, false);
        try {
          localStorage.setItem(KEY, t.dataset.lang);
        } catch (e) {}
      });
      t.addEventListener("keydown", function (e) {
        var next = null;
        if (e.key === "ArrowRight") next = tabs[(i + 1) % tabs.length];
        else if (e.key === "ArrowLeft") next = tabs[(i - 1 + tabs.length) % tabs.length];
        else if (e.key === "Home") next = tabs[0];
        else if (e.key === "End") next = tabs[tabs.length - 1];
        if (!next) return;
        e.preventDefault();
        select(next.dataset.lang, true);
      });
    });

    var saved = null;
    try {
      saved = localStorage.getItem(KEY);
    } catch (e) {}
    var known = tabs.some(function (t) {
      return t.dataset.lang === saved;
    });
    select(known ? saved : tabs[0].dataset.lang, false);
  });

  document.querySelectorAll("[data-copy]").forEach(function (button) {
    button.addEventListener("click", function () {
      var done = function () {
        button.textContent = "Copied";
        setTimeout(function () {
          button.textContent = "Copy";
        }, 1600);
      };
      if (navigator.clipboard) navigator.clipboard.writeText(button.dataset.copy).then(done, function () {});
    });
  });
})();

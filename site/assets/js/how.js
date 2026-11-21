// How it works: the pairing stepper, the contents rail, one control for every details panel, and
// the relay figure's packets. Without script the page reads in full: every step and caption shows,
// and each details panel opens on its own.
(function () {
  var reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  // The rail's height, so the CSS can hold it at the middle of the screen.
  var toc = document.querySelector(".toc");
  if (toc) {
    var sizeToc = function () { toc.style.setProperty("--toc-h", toc.offsetHeight + "px"); };
    sizeToc();
    addEventListener("resize", sizeToc);
  }

  // Pairing, one step at a time.
  var seq = document.querySelector("[data-seq]");
  if (seq) {
    var groups = seq.querySelectorAll(".sq");
    var items = seq.querySelectorAll(".seq-list li");
    var prev = seq.querySelector("[data-seq-prev]");
    var next = seq.querySelector("[data-seq-next]");
    var pos = seq.querySelector("[data-seq-pos]");
    var last = items.length - 1;
    var at = 0;
    var go = function (n) {
      at = Math.max(0, Math.min(last, n));
      [groups, items].forEach(function (list) {
        Array.prototype.forEach.call(list, function (el) {
          var i = Number(el.dataset.sq);
          el.classList.toggle("is-past", i < at);
          el.classList.toggle("is-now", i === at);
        });
      });
      prev.disabled = at === 0;
      next.textContent = at === last ? "Start again" : "Next";
      pos.textContent = "Step " + (at + 1) + " of " + items.length;
    };
    seq.classList.add("is-live");
    seq.querySelector(".seq-ctl").hidden = false;
    prev.addEventListener("click", function () { go(at - 1); });
    next.addEventListener("click", function () { go(at === last ? 0 : at + 1); });
    go(0);
  }

  // Printing opens every details panel, then restores what the reader had open.
  var panels = Array.prototype.slice.call(document.querySelectorAll("details.more"));
  if (panels.length) {
    var before = null;
    addEventListener("beforeprint", function () {
      before = panels.map(function (d) { return d.open; });
      panels.forEach(function (d) { d.open = true; });
    });
    addEventListener("afterprint", function () {
      if (before) panels.forEach(function (d, i) { d.open = before[i]; });
      before = null;
    });
  }

  // Contents: an open rail on wide screens, a closed list on narrow ones; marks where you are.
  var toc = document.querySelector("[data-toc]");
  if (toc) {
    var wide = matchMedia("(min-width: 1024px)");
    var fit = function () { toc.open = wide.matches; };
    fit();
    wide.addEventListener("change", fit);
    toc.addEventListener("toggle", function () { if (wide.matches && !toc.open) toc.open = true; });
    var links = Array.prototype.slice.call(toc.querySelectorAll("a"));
    links.forEach(function (a) {
      a.addEventListener("click", function () { if (!wide.matches) toc.open = false; });
    });
    var parts = links.map(function (a) { return document.getElementById(a.hash.slice(1)); });
    var mark = function (id) {
      var idx = parts.findIndex(function (s) { return s.id === id; });
      links.forEach(function (a, i) {
        a.parentNode.classList.toggle("is-past", i < idx);
        if (i === idx) a.setAttribute("aria-current", "location");
        else a.removeAttribute("aria-current");
      });
    };
    var spy = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { if (e.isIntersecting) mark(e.target.id); });
    }, { rootMargin: "-30% 0px -65% 0px" });
    parts.forEach(function (s) { spy.observe(s); });
  }

  // Relay: sealed packets travel only while the figure is on screen and motion is welcome.
  var relay = document.querySelector("[data-relay]");
  if (relay && !reduced) {
    new IntersectionObserver(function (entries) {
      var on = entries[0].isIntersecting;
      if (on) relay.classList.add("is-on");
      relay.classList.toggle("is-paused", !on);
    }, { threshold: 0.2 }).observe(relay);
  }
})();

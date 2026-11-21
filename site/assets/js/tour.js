// The pairing tour in the hero. Without script, step 1 shows and the step buttons do nothing.
// The panes of each device share one grid cell, so a device keeps its tallest pane's height.
// It advances on its own only while visible, and never when the reader asks for reduced motion.
(function () {
  var LINK = [
    { label: "not connected", sub: "", pct: "0" },
    { label: "hybrid post-quantum handshake", sub: "encrypted after message 1", pct: "40" },
    { label: "waiting for a person", sub: "socket closed", pct: "60" },
    { label: "paired", sub: "0 permissions", pct: "80" },
    { label: "direct", sub: "notes.sync only", pct: "100" },
  ];
  var INTERVAL = 3400;

  var tour = document.querySelector("[data-tour]");
  if (!tour) return;
  var panes = tour.querySelectorAll("[data-step]");
  var buttons = tour.querySelectorAll("[data-goto]");
  var play = tour.querySelector("[data-play]");
  var label = tour.querySelector("[data-link-label]");
  var sub = tour.querySelector("[data-link-sub]");
  var fill = tour.querySelector("[data-link-fill]");
  var reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  var step = 0;
  var playing = !reduced;
  var visible = false;
  var timer = null;

  function show(n) {
    step = n;
    panes.forEach(function (p) {
      var off = Number(p.dataset.step) !== n;
      p.hidden = false;
      p.inert = off;
      p.setAttribute("aria-hidden", off ? "true" : "false");
    });
    buttons.forEach(function (b) {
      b.setAttribute("aria-pressed", Number(b.dataset.goto) === n ? "true" : "false");
    });
    label.textContent = LINK[n].label;
    sub.textContent = LINK[n].sub;
    fill.dataset.pct = LINK[n].pct;
  }

  function schedule() {
    clearInterval(timer);
    timer = null;
    if (playing && visible && !document.hidden) {
      timer = setInterval(function () {
        show((step + 1) % LINK.length);
      }, INTERVAL);
    }
    play.textContent = playing ? "Pause" : "Play";
  }

  buttons.forEach(function (b) {
    b.addEventListener("click", function () {
      playing = false;
      show(Number(b.dataset.goto));
      schedule();
    });
  });
  tour.classList.add("is-live");
  play.hidden = false;
  play.addEventListener("click", function () {
    playing = !playing;
    schedule();
  });
  document.addEventListener("visibilitychange", schedule);
  new IntersectionObserver(function (entries) {
    visible = entries[0].isIntersecting;
    schedule();
  }).observe(tour);

  show(0);
})();

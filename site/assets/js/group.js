// The groups diagram. One loop: each member pairs with the root, the root's signed list lands on
// every member, the members link to each other, then the root removes the server and its links
// are cut. The markup is the end state, so without script, or with reduced motion, the figure shows
// the mesh with the server removed. Motion runs only while the diagram is on screen and the tab is
// visible, and Pause stops it.
(function () {
  var fig = document.querySelector("[data-grp]");
  if (!fig) return;
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  var NS = "http://www.w3.org/2000/svg";
  var svg = fig.querySelector("svg");
  var L = {};
  fig.querySelectorAll("[data-l]").forEach(function (p) {
    L[p.dataset.l] = p;
  });
  var D = {};
  fig.querySelectorAll("[data-d]").forEach(function (g) {
    D[g.dataset.d] = g;
  });
  var pkLayer = fig.querySelector("[data-grp-pk]");
  var relay = fig.querySelector("[data-grp-relay]");
  var pill = fig.querySelector("[data-grp-pill]");
  var pillText = fig.querySelector("[data-grp-pilltext]");
  var nEl = fig.querySelector("[data-grp-n]");
  var lEl = fig.querySelector("[data-grp-l]");
  var sEl = fig.querySelector("[data-grp-s]");
  var phases = fig.querySelectorAll(".grp-phases li");
  var play = fig.querySelector("[data-grp-play]");
  // Device, its line to the root, and how it joined.
  var MEMBERS = [
    ["phone", "s0", "paired by code"],
    ["laptop", "s1", "paired by code"],
    ["nas", "s2", "enrolled, token"],
    ["server", "s3", "enrolled, token"],
  ];
  var MESH = ["m0", "m1", "m2", "m3", "m4", "m5"];
  var SERVER = ["s3", "m3", "m4", "m5"];
  var motion = true;
  var visible = false;
  var started = false;
  var flows = {};

  // A queue of timed steps whose clock stops while the diagram is paused or off screen.
  var queue = [];
  var timer = null;
  var due = 0;
  var left = 0;
  function running() {
    return motion && visible && !document.hidden;
  }
  function arm() {
    clearTimeout(timer);
    timer = null;
    if (!queue.length || !running()) return;
    due = Date.now() + left;
    timer = setTimeout(fire, left);
  }
  function fire() {
    queue.shift().fn();
    left = queue.length ? queue[0].wait : 0;
    arm();
  }
  function hold() {
    if (timer) left = Math.max(0, due - Date.now());
    clearTimeout(timer);
    timer = null;
  }
  function plan(events) {
    var last = 0;
    queue = events.map(function (e) {
      var item = { wait: e[0] - last, fn: e[1] };
      last = e[0];
      return item;
    });
    left = queue.length ? queue[0].wait : 0;
    arm();
  }

  function line(id, state) {
    L[id].setAttribute("class", "gl is-" + state + (id === "m2" ? " gl-relay" : ""));
  }
  function off(el, yes) {
    el.classList.toggle("is-off", yes);
  }
  function role(d, text) {
    D[d].querySelector("[data-r]").textContent = text;
  }
  function marker(d, on) {
    off(D[d].querySelector(".gm"), !on);
  }
  function status(n, label, sub, cut) {
    nEl.textContent = "0" + n;
    lEl.textContent = label;
    sEl.textContent = sub;
    fig.classList.toggle("is-cut", !!cut);
    phases.forEach(function (p) {
      p.classList.toggle("is-now", Number(p.dataset.p) === n);
    });
  }

  // A packet moving along a line: hs is a handshake (out, back and out), list goes from the root to
  // a member, data loops for as long as the link carries traffic.
  function packet(id, kind, dur, back) {
    var size = kind === "list" ? 8 : kind === "data" ? 5 : 7;
    var r = document.createElementNS(NS, "rect");
    r.setAttribute("x", -size / 2);
    r.setAttribute("y", -size / 2);
    r.setAttribute("width", size);
    r.setAttribute("height", size);
    r.setAttribute("class", "pk-" + kind);
    var a = document.createElementNS(NS, "animateMotion");
    a.setAttribute("path", L[id].getAttribute("d"));
    a.setAttribute("dur", dur + "ms");
    a.setAttribute("begin", "indefinite");
    a.setAttribute("calcMode", "linear");
    if (kind === "hs") {
      a.setAttribute("keyPoints", "0;1;0;1");
      a.setAttribute("keyTimes", "0;0.33;0.67;1");
    } else if (back) {
      a.setAttribute("keyPoints", "1;0");
      a.setAttribute("keyTimes", "0;1");
    }
    if (kind === "data") a.setAttribute("repeatCount", "indefinite");
    else a.setAttribute("fill", "freeze");
    r.appendChild(a);
    pkLayer.appendChild(r);
    if (kind !== "data") {
      a.addEventListener("endEvent", function () {
        r.remove();
      });
      setTimeout(function () {
        r.remove();
      }, dur + 60);
    }
    try {
      a.beginElement();
    } catch (e) {
      r.remove();
    }
    return r;
  }
  function flow(id) {
    flows[id] = [packet(id, "data", 3200, false), packet(id, "data", 3200, true)];
  }
  function stopFlow(id) {
    (flows[id] || []).forEach(function (r) {
      r.remove();
    });
    delete flows[id];
  }

  function reset() {
    Object.keys(flows).forEach(stopFlow);
    pkLayer.textContent = "";
    MEMBERS.forEach(function (m) {
      line(m[1], "idle");
      marker(m[0], false);
      role(m[0], m[2]);
    });
    MESH.forEach(function (id) {
      line(id, "off");
    });
    marker("root", false);
    D.server.classList.remove("is-gone");
    off(relay, true);
    off(pill, true);
    status(1, "pairing with the root", "one member at a time");
  }

  function loop() {
    // Pairing runs slower than the rest, so each handshake can be followed. P shifts every later phase.
    var P = 2250;
    var ev = [[0, reset]];
    MEMBERS.forEach(function (m, i) {
      var t = 700 + i * 1600;
      ev.push([t, function () {
        line(m[1], "try");
        packet(m[1], "hs", 1500);
        status(1, "pairing with the root", m[0].replace("nas", "NAS") + " · " + m[2]);
      }]);
      ev.push([t + 1550, function () {
        line(m[1], "win");
      }]);
    });
    ev.push([P + 5200, function () {
      status(2, "the root signs the list", "list v1 · 5 of 32");
      pillText.textContent = "list v1 · signed";
      off(pill, false);
      marker("root", true);
      MEMBERS.forEach(function (m) {
        packet(m[1], "list", 750);
      });
    }]);
    ev.push([P + 5950, function () {
      MEMBERS.forEach(function (m) {
        marker(m[0], true);
        role(m[0], "member");
      });
    }]);
    ev.push([P + 7200, function () {
      status(3, "members link directly", "each pair with its own keys");
      MEMBERS.forEach(function (m) {
        line(m[1], "quiet");
      });
      role("phone", "member · away");
    }]);
    MESH.forEach(function (id, j) {
      var t = P + 7500 + j * 380;
      ev.push([t, function () {
        line(id, "try");
        packet(id, "hs", 650);
        if (id === "m2") off(relay, false);
      }]);
      ev.push([t + 700, function () {
        line(id, "win");
        flow(id);
      }]);
    });
    ev.push([P + 10300, function () {
      status(3, "members link directly", "6 links · open on first send");
    }]);
    ev.push([P + 12400, function () {
      status(4, "one is removed", "the root signs list v2");
      pillText.textContent = "list v2 · signed";
      ["s0", "s1", "s2"].forEach(function (id) {
        packet(id, "list", 750);
      });
    }]);
    ev.push([P + 13150, function () {
      SERVER.forEach(function (id) {
        stopFlow(id);
        line(id, "cut");
      });
      D.server.classList.add("is-gone");
      role("server", "removed");
      status(4, "one is removed", "server cut off from every member", true);
    }]);
    ev.push([P + 17400, loop]);
    plan(ev);
  }

  function sync() {
    fig.classList.toggle("is-paused", !running());
    if (running()) svg.unpauseAnimations();
    else svg.pauseAnimations();
    if (!started && running()) {
      started = true;
      loop();
      return;
    }
    if (running()) arm();
    else hold();
  }

  fig.classList.add("is-live");
  play.hidden = false;
  play.addEventListener("click", function () {
    motion = !motion;
    play.textContent = motion ? "Pause" : "Play";
    sync();
  });
  document.addEventListener("visibilitychange", sync);
  new IntersectionObserver(function (entries) {
    visible = entries[0].isIntersecting;
    sync();
  }, { threshold: 0.35 }).observe(fig);
})();

// The paths diagram. Each scenario walks the six paths nearest first: a path that does not apply
// greys out, a blocked one fails, and the first to finish the handshake carries sealed data.
// Without script, or with reduced motion, each scenario shows its end state. Motion runs only
// while the diagram is on screen and the tab is visible, and Pause stops it.
(function () {
  var fig = document.querySelector("[data-net]");
  if (!fig) return;

  var WORD = { block: "blocked", wrong: "wrong host", drop: "dropped", win: "in use" };
  var AT = { block: "mid", wrong: "end", drop: "start" };
  var DEV = {
    phone: ["ni-phone", "phone", "client"],
    browser: ["ni-browser", "browser tab", "client only"],
  };
  var NO = "not in browser";
  // Outcomes per path, nearest first. A plain word means the path does not apply. Paths after the
  // winner are not used unless a word says otherwise.
  var SCENES = [
    { dev: "phone", net: "home Wi-Fi", steps: ["other machine", "win"] },
    { dev: "phone", net: "mobile data", steps: ["other machine", "wrong", "no tailnet", "win"] },
    { dev: "phone", net: "office network", steps: ["other machine", "block", "no tailnet", "block", "win"] },
    {
      dev: "phone", net: "home Wi-Fi", steps: ["other machine", "win"],
      then: { net: "mobile data", steps: ["other machine", "drop", "no tailnet", "win"] },
    },
    { dev: "browser", net: "any network", steps: [NO, NO, NO, "via iroh relay", "win", NO] },
  ];
  var P2P = 3;
  var WAIT = 1400;
  var HOLD = 4800;

  var tabs = Array.prototype.slice.call(fig.querySelectorAll('[role="tab"]'));
  var panels = fig.querySelectorAll(".net-cap");
  var play = fig.querySelector("[data-net-play]");
  var ic = fig.querySelector("[data-dev-ic]");
  var devName = fig.querySelector("[data-dev-name]");
  var devRole = fig.querySelector("[data-dev-role]");
  var devNet = fig.querySelector("[data-dev-net]");
  var pairRow = fig.querySelector(".lane-pair");
  var pairWord = fig.querySelector("[data-pair]");
  var lanes = Array.prototype.map.call(fig.querySelectorAll("[data-lane]"), function (el) {
    return { el: el, s: el.querySelector(".lane-s"), t: el.querySelector(".lane-t"), probe: el.querySelector(".lane-probe"), bar: el.querySelector(".lane-bar") };
  });
  var fans = Array.prototype.map.call(fig.querySelectorAll("[data-fan]"), function (svg) {
    return svg.querySelectorAll("path");
  });
  var reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  var motion = !reduced;
  var auto = true;
  var visible = false;
  var started = false;
  var scene = 0;

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
    clearTimeout(timer);
    queue = events.map(function (e) {
      var item = { wait: e[0] - last, fn: e[1] };
      last = e[0];
      return item;
    });
    left = queue.length ? queue[0].wait : 0;
    arm();
  }

  function set(i, state, word, at) {
    var lane = lanes[i];
    lane.el.className = "lane is-" + state;
    fans.forEach(function (paths) {
      paths[i].setAttribute("class", "is-" + state);
      if (state === "win") paths[i].parentNode.insertBefore(paths[i], paths[i].parentNode.lastElementChild);
    });
    lane.s.textContent = word;
    lane.bar.dataset.at = at || "";
    lane.probe.className = "lane-probe";
    var pk = lane.t.querySelector(".lane-pk");
    if (pk && state !== "win") pk.remove();
    if (state === "win" && !pk && !reduced) {
      pk = document.createElement("span");
      pk.className = "lane-pk";
      for (var k = 0; k < 4; k++) pk.appendChild(document.createElement("i"));
      lane.t.appendChild(pk);
    }
  }
  function probe(i, kind) {
    var p = lanes[i].probe;
    p.className = "lane-probe";
    void p.offsetWidth;
    p.className = "lane-probe go-" + kind;
  }
  function settle(i, o) {
    if (WORD[o]) set(i, o === "win" ? "win" : "fail", WORD[o], AT[o]);
    else set(i, "idle", o);
  }
  function rest(steps, from) {
    for (var j = from; j < lanes.length; j++) set(j, "idle", steps[j] && !WORD[steps[j]] ? steps[j] : "not used");
  }
  function device(s, net) {
    var d = DEV[s.dev];
    ic.setAttribute("href", "#" + d[0]);
    devName.textContent = d[1];
    devRole.textContent = d[2];
    devNet.textContent = net;
    devNet.classList.remove("is-new");
  }
  function pair(word, hot) {
    pairWord.textContent = word;
    pairRow.classList.toggle("is-hot", !!hot);
  }

  // Adds the events of one pass over the paths, from time t, to ev and returns when it ends.
  function pass(steps, t, ev) {
    var t0 = t;
    // Every path starts open. Peer-to-peer waits briefly, so a nearer path can win first.
    ev.push([t, function () {
      lanes.forEach(function (_, i) {
        if (steps[i] !== "drop") set(i, "try", i === P2P && (!steps[i] || WORD[steps[i]]) ? "waits" : "");
      });
    }]);
    t += 480;
    for (var i = 0; i < lanes.length; i++) {
      var o = steps[i];
      if (o === undefined) break;
      if (!WORD[o] || o === "drop") {
        ev.push([t, settle.bind(null, i, o)]);
        t += 380;
        continue;
      }
      if (i === P2P && t < t0 + WAIT) t = t0 + WAIT;
      if (o === "block") {
        ev.push([t, function (i) { set(i, "try", "trying"); probe(i, "half"); }.bind(null, i)]);
        t += 1000;
      } else {
        ev.push([t, function (i, k) { set(i, "try", "handshake"); probe(i, k); }.bind(null, i, o === "win" ? "hs3" : "hs2")]);
        t += o === "win" ? 1620 : 1140;
      }
      ev.push([t, settle.bind(null, i, o)]);
      if (o === "win") {
        ev.push([t, rest.bind(null, steps, i + 1)]);
        return t;
      }
      t += 300;
    }
    return t;
  }

  function end(n) {
    var s = SCENES[n];
    var last = s.then || s;
    device(s, last.net);
    last.steps.forEach(function (o, i) {
      settle(i, o);
    });
    rest(last.steps, last.steps.indexOf("win") + 1);
    pair(s.then ? "same pairing" : "paired", !!s.then);
  }

  function show(n, animate) {
    scene = n;
    tabs.forEach(function (t, i) {
      t.setAttribute("aria-selected", i === n ? "true" : "false");
      t.tabIndex = i === n ? 0 : -1;
    });
    panels.forEach(function (p, i) {
      p.inert = i !== n;
      p.setAttribute("aria-hidden", i === n ? "false" : "true");
    });
    if (!animate) {
      plan([]);
      end(n);
      return;
    }
    var s = SCENES[n];
    var ev = [];
    device(s, s.net);
    pair("paired");
    var t = pass(s.steps, 0, ev);
    if (s.then) {
      t += 2800;
      ev.push([t, function () {
        devNet.textContent = s.then.net;
        devNet.classList.add("is-new");
        set(1, "fail", WORD.drop, AT.drop);
        pair("handshake again", true);
      }]);
      t = pass(s.then.steps, t + 1100, ev);
      ev.push([t, function () {
        pair("same pairing", true);
      }]);
    }
    ev.push([t + HOLD, function () {
      if (auto) show((scene + 1) % SCENES.length, true);
    }]);
    plan(ev);
  }

  function sync() {
    fig.classList.toggle("is-paused", !running());
    if (!started && running()) {
      started = true;
      show(scene, true);
      return;
    }
    if (running()) arm();
    else hold();
  }

  fig.classList.add("is-live");
  panels.forEach(function (p, i) {
    p.setAttribute("role", "tabpanel");
    p.setAttribute("aria-labelledby", tabs[i].id);
    p.tabIndex = 0;
  });
  fig.querySelector(".net-pick").hidden = false;
  tabs.forEach(function (t, i) {
    t.addEventListener("click", function () {
      auto = false;
      show(i, running());
    });
    t.addEventListener("keydown", function (e) {
      var k = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 }[e.key];
      if (k === undefined) return;
      e.preventDefault();
      k = (k + tabs.length) % tabs.length;
      tabs[k].focus();
      auto = false;
      show(k, running());
    });
  });
  if (!reduced) {
    play.hidden = false;
    play.addEventListener("click", function () {
      motion = !motion;
      play.textContent = motion ? "Pause" : "Play";
      sync();
    });
  }
  document.addEventListener("visibilitychange", sync);
  new IntersectionObserver(function (entries) {
    visible = entries[0].isIntersecting;
    sync();
  }, { threshold: 0.35 }).observe(fig);

  show(0, false);
})();

// Colour theme: follows the system until the reader picks one, then remembers the pick. Loaded in
// <head> without defer so the saved theme applies before first paint.
(function () {
  var KEY = "wiki-theme"; // the docs renderer reads the same key, so the choice carries over
  var root = document.documentElement;
  var saved = null;
  try {
    saved = localStorage.getItem(KEY);
  } catch (e) {}
  if (saved === "light" || saved === "dark") root.dataset.theme = saved;

  function current() {
    if (root.dataset.theme) return root.dataset.theme;
    return matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  document.addEventListener("DOMContentLoaded", function () {
    var button = document.querySelector("[data-theme-toggle]");
    if (!button) return;
    function label() {
      button.setAttribute("aria-label", current() === "dark" ? "Switch to light theme" : "Switch to dark theme");
    }
    label();
    button.addEventListener("click", function () {
      var next = current() === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      try {
        localStorage.setItem(KEY, next);
      } catch (e) {}
      label();
    });
  });
})();

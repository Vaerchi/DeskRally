/* Applies the stored theme before first paint. Mirrors src/lib/theme.ts (a test keeps them in step).
   An external file because the CSP is script-src 'self'. Explicit choice only; System = no attribute. */
(function () {
  try {
    var pref = window.localStorage.getItem("deskrally.theme");
    if (pref !== "light" && pref !== "dark") return;
    document.documentElement.setAttribute("data-theme", pref);
    var color = pref === "light" ? "#f6f8fa" : "#0e1116";
    var metas = document.querySelectorAll('meta[name="theme-color"]');
    for (var i = 0; i < metas.length; i++) {
      metas[i].setAttribute("data-default-color", metas[i].getAttribute("content") || "");
      metas[i].setAttribute("content", color);
    }
  } catch (e) { /* no storage: System */ }
})();

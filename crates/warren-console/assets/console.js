// warren console. Progressive enhancement only: every page works without
// this script. Hand-written; no build step.
"use strict";

(function () {
  // Ask before destructive actions.
  document.addEventListener("submit", function (event) {
    var form = event.target;
    var question = form.getAttribute("data-confirm");
    if (question && !window.confirm(question)) {
      event.preventDefault();
    }
  });

  // Filter table rows as you type.
  function bindFilters(root) {
    root.querySelectorAll("input[data-filter]").forEach(function (input) {
      var table = document.getElementById(input.getAttribute("data-filter"));
      if (!table) {
        return;
      }
      input.addEventListener("input", function () {
        var needle = input.value.trim().toLowerCase();
        table.querySelectorAll("tbody tr").forEach(function (row) {
          var text = row.textContent.toLowerCase();
          row.hidden = needle !== "" && text.indexOf(needle) === -1;
        });
      });
    });
  }

  // Keep "3 min ago" current.
  function relative(then) {
    var delta = Math.round((Date.now() - then) / 1000);
    var span = Math.abs(delta);
    var amount;
    if (span < 45) {
      return delta >= 0 ? "just now" : "in a moment";
    } else if (span < 5400) {
      amount = Math.round(span / 60) + " min";
    } else if (span < 129600) {
      amount = Math.round(span / 3600) + " h";
    } else {
      amount = Math.round(span / 86400) + " d";
    }
    return delta >= 0 ? amount + " ago" : "in " + amount;
  }

  function refreshTimes(root) {
    root.querySelectorAll("time[data-rel]").forEach(function (el) {
      var then = Date.parse(el.getAttribute("datetime"));
      if (!isNaN(then)) {
        el.textContent = relative(then);
      }
    });
  }

  // Reload live sections in place, without losing the reader's place,
  // while the tab is visible and nobody is typing.
  function bindRefresh() {
    var live = document.querySelector("[data-refresh]");
    if (!live) {
      return;
    }
    var seconds = parseInt(live.getAttribute("data-refresh"), 10) || 15;
    window.setInterval(function () {
      var active = document.activeElement;
      if (document.hidden || (active && active.tagName === "INPUT")) {
        return;
      }
      fetch(window.location.href, { credentials: "same-origin", headers: { "Accept": "text/html" } })
        .then(function (resp) {
          if (!resp.ok || resp.redirected) {
            throw new Error("not refreshed");
          }
          return resp.text();
        })
        .then(function (text) {
          var doc = new DOMParser().parseFromString(text, "text/html");
          var fresh = doc.querySelector("[data-refresh]");
          var current = document.querySelector("[data-refresh]");
          if (fresh && current) {
            current.replaceWith(document.importNode(fresh, true));
            var now = document.querySelector("[data-refresh]");
            bindFilters(now);
            refreshTimes(now);
          }
        })
        .catch(function () {});
    }, seconds * 1000);
  }

  document.addEventListener("DOMContentLoaded", function () {
    bindFilters(document);
    refreshTimes(document);
    window.setInterval(function () { refreshTimes(document); }, 30000);
    bindRefresh();
  });
})();

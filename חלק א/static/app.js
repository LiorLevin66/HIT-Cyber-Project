// Live feedback only. The server enforces every rule again on submit.
(function () {
  var input = document.querySelector("[data-password-input]");
  var list = document.getElementById("reqs");
  if (!input || !list) return;

  var rules = {
    length: function (v) { return v.length >= parseInt(list.dataset.min, 10); },
    upper: function (v) { return /[A-Z]/.test(v); },
    lower: function (v) { return /[a-z]/.test(v); },
    digit: function (v) { return /[0-9]/.test(v); },
    special: function (v) { return /[!-\/:-@\[-`{-~]/.test(v); }
  };

  function update() {
    list.querySelectorAll("li").forEach(function (li) {
      var test = rules[li.dataset.rule];
      li.classList.toggle("met", !!test && test(input.value));
    });
  }
  input.addEventListener("input", update);
  update();

  var confirm = document.getElementById("confirm");
  if (!confirm) return;
  var note = document.createElement("p");
  note.className = "match-note";
  note.setAttribute("aria-live", "polite");
  confirm.parentNode.appendChild(note);

  function compare() {
    if (!confirm.value) { note.textContent = ""; note.className = "match-note"; return; }
    var same = confirm.value === input.value;
    note.textContent = same ? "Passwords match." : "Passwords don't match yet.";
    note.className = "match-note " + (same ? "ok" : "bad");
  }
  confirm.addEventListener("input", compare);
  input.addEventListener("input", compare);
})();

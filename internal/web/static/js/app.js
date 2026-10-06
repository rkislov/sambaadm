(function () {
  function csrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") : "";
  }

  document.addEventListener("htmx:configRequest", function (e) {
    var token = csrfToken();
    if (token) {
      e.detail.headers["X-CSRF-Token"] = token;
    }
  });

  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (!form || form.tagName !== "FORM") return;
    if ((form.method || "").toLowerCase() !== "post") return;
    if (form.querySelector('input[name="csrf_token"]')) return;
    var token = csrfToken();
    if (!token) return;
    var input = document.createElement("input");
    input.type = "hidden";
    input.name = "csrf_token";
    input.value = token;
    form.appendChild(input);
  });

  var presets = {
    domain_read: {
      valid: '"Domain Users"', write: "", read: "", fgroup: "domain users",
      ro: true, guest: false, mode: "0755",
      acl: "g:domain users:r-x,o::---", dacl: "g:domain users:r-x,o::---"
    },
    domain_rw: {
      valid: '"Domain Users"', write: '"Domain Users"', read: "", fgroup: "domain users",
      ro: false, guest: false, mode: "0770",
      acl: "g:domain users:rwx,o::---", dacl: "g:domain users:rwx,o::---"
    },
    domain_group_rw: {
      valid: '@"Finance"', write: '@"Finance"', read: "", fgroup: "finance",
      ro: false, guest: false, mode: "0770",
      acl: "g:finance:rwx,o::---", dacl: "g:finance:rwx,o::---"
    },
    users_only: {
      valid: "alice,bob", write: "alice", read: "", fgroup: "",
      ro: false, guest: false, mode: "0750",
      acl: "u:alice:rwx,u:bob:r-x,o::---", dacl: "u:alice:rwx,u:bob:r-x,o::---"
    },
    authenticated: {
      valid: "", write: "", read: "", fgroup: "domain users",
      ro: false, guest: false, mode: "0775",
      acl: "g:domain users:rwx,o::r-x", dacl: "g:domain users:rwx,o::r-x"
    },
    guest_public: {
      valid: "", write: "", read: "", fgroup: "",
      ro: true, guest: true, mode: "0755",
      acl: "o::r-x", dacl: "o::r-x"
    },
    custom: null
  };

  function setVal(id, v) {
    var el = document.getElementById(id);
    if (el) el.value = v == null ? "" : v;
  }
  function setCheck(id, on) {
    var el = document.getElementById(id);
    if (el) el.checked = !!on;
  }

  document.addEventListener("change", function (e) {
    var t = e.target;
    if (!t || !t.matches || !t.matches('input[name="preset"][data-preset]')) return;
    var p = presets[t.value];
    if (!p) return;
    setVal("f-valid", p.valid);
    setVal("f-write", p.write);
    setVal("f-read", p.read);
    setVal("f-fgroup", p.fgroup);
    setVal("f-mode", p.mode);
    setVal("f-acl", p.acl);
    setVal("f-dacl", p.dacl);
    setCheck("f-ro", p.ro);
    setCheck("f-guest", p.guest);
  });
})();

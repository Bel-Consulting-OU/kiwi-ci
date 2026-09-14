/* Kiwi CI dashboard client. Dependency-free.
 *
 * Security constraints honored throughout:
 *   - user-provided data is rendered exclusively via textContent and
 *     createElement (never innerHTML);
 *   - the admin token is sent once to POST /api/v1/login and never stored;
 *     the session cookie handles all later requests;
 *   - mutating requests authenticated by the session cookie carry the
 *     double-submit CSRF token in the X-Kiwi-CSRF header.
 */
"use strict";

(() => {
  const POLL_MS = 4000;
  const state = { csrf: "", authed: false, selectedRun: null };

  const $ = (sel) => document.querySelector(sel);
  const conn = $("#conn");
  const loginForm = $("#login");
  const logoutBtn = $("#logout");
  const statsEl = $("#stats");
  const runsBody = $("#runs tbody");
  const jobsBody = $("#jobs tbody");
  const detail = $("#detail");
  const errorEl = $("#error");

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function showError(msg) {
    errorEl.textContent = msg || "";
    errorEl.classList.toggle("hidden", !msg);
  }

  function setConn(ok) {
    conn.textContent = ok ? "online" : "offline";
    conn.classList.toggle("hidden", false);
  }

  async function api(path, options) {
    const opts = Object.assign({ credentials: "same-origin" }, options || {});
    opts.headers = Object.assign({}, opts.headers || {});
    if (opts.body !== undefined && typeof opts.body === "string") {
      opts.headers["Content-Type"] = "application/json";
    }
    if (opts.method && opts.method !== "GET" && state.csrf) {
      opts.headers["X-Kiwi-CSRF"] = state.csrf;
    }
    const resp = await fetch(path, opts);
    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      throw new Error(resp.status + " " + (text || resp.statusText));
    }
    if (resp.status === 204) return null;
    const ct = resp.headers.get("Content-Type") || "";
    return ct.indexOf("application/json") >= 0 ? resp.json() : resp.text();
  }

  function setAuthed() {
    state.authed = true;
    loginForm.classList.add("hidden");
    logoutBtn.classList.remove("hidden");
  }

  function setSignedOut() {
    state.authed = false;
    state.csrf = "";
    loginForm.classList.remove("hidden");
    logoutBtn.classList.add("hidden");
    detail.classList.add("hidden");
    runsBody.replaceChildren();
    statsEl.replaceChildren();
  }

  loginForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const token = $("#token").value;
    try {
      const resp = await fetch("/api/v1/login", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: token }),
      });
      if (!resp.ok) throw new Error(resp.status + " " + (await resp.text()));
      state.csrf = resp.headers.get("X-Kiwi-CSRF") || "";
      $("#token").value = "";
      setAuthed();
      showError("");
      refresh();
    } catch (err) {
      showError("Sign in failed: " + err.message);
    }
  });

  logoutBtn.addEventListener("click", async () => {
    try {
      await fetch("/api/v1/logout", { credentials: "same-origin" });
    } catch (err) {
      /* the cookie clears server-side regardless */
    }
    setSignedOut();
  });

  function statusClass(status) {
    const known = new Set([
      "pending", "queued", "running", "success", "failure",
      "cancelled", "skipped", "blocked", "waiting_approval",
    ]);
    return known.has(status) ? status : "";
  }

  function statusPill(status) {
    return el("span", "status " + statusClass(status), status);
  }

  function age(created) {
    const ms = Date.now() - new Date(created).getTime();
    if (!Number.isFinite(ms) || ms < 0) return "";
    const s = Math.round(ms / 1000);
    if (s < 60) return s + "s";
    const m = Math.round(s / 60);
    if (m < 60) return m + "m";
    const h = Math.round(m / 60);
    if (h < 48) return h + "h";
    return Math.round(h / 24) + "d";
  }

  function renderStats(runs) {
    statsEl.replaceChildren();
    const counts = { total: runs.length, running: 0, success: 0, failure: 0, other: 0 };
    for (const run of runs) {
      if (run.status === "success") counts.success++;
      else if (run.status === "failure") counts.failure++;
      else if (run.status === "running" || run.status === "queued" || run.status === "pending") counts.running++;
      else counts.other++;
    }
    const rows = [
      ["runs", counts.total],
      ["active", counts.running],
      ["success", counts.success],
      ["failure", counts.failure],
      ["other", counts.other],
    ];
    for (const [label, n] of rows) {
      const stat = el("div", "stat");
      stat.appendChild(el("div", "n", n));
      stat.appendChild(el("div", "l", label));
      statsEl.appendChild(stat);
    }
  }

  function renderRuns(runs) {
    renderStats(runs);
    runsBody.replaceChildren();
    for (const run of runs) {
      const tr = el("tr");
      tr.appendChild(el("td", "muted", run.id));
      const tdStatus = el("td");
      tdStatus.appendChild(statusPill(run.status));
      tr.appendChild(tdStatus);
      tr.appendChild(el("td", null, run.event));
      tr.appendChild(el("td", null, run.repo || run.repo_full_name));
      tr.appendChild(el("td", null, run.trusted ? "yes" : "no"));
      tr.appendChild(el("td", "muted", age(run.created_at)));
      const tdCancel = el("td");
      if (state.authed && !isTerminal(run.status)) {
        const btn = el("button", null, "Cancel");
        btn.addEventListener("click", async (ev) => {
          ev.stopPropagation();
          try {
            await api("/api/v1/runs/" + encodeURIComponent(run.id) + "/cancel", {
              method: "POST",
              body: "{}",
            });
            refresh();
          } catch (err) {
            showError("Cancel failed: " + err.message);
          }
        });
        tdCancel.appendChild(btn);
      }
      tr.appendChild(tdCancel);
      tr.addEventListener("click", () => selectRun(run.id));
      runsBody.appendChild(tr);
    }
  }

  function isTerminal(status) {
    return ["success", "failure", "cancelled", "skipped", "blocked"].indexOf(status) >= 0;
  }

  async function selectRun(runID) {
    state.selectedRun = runID;
    detail.classList.remove("hidden");
    jobsBody.replaceChildren(el("tr", null, "loading"));
    try {
      const jobs = await api("/api/v1/runs/" + encodeURIComponent(runID) + "/jobs");
      renderJobs(jobs);
    } catch (err) {
      jobsBody.replaceChildren();
      showError("Could not load jobs: " + err.message);
    }
  }

  function renderJobs(jobs) {
    jobsBody.replaceChildren();
    for (const job of jobs) {
      const tr = el("tr");
      tr.appendChild(el("td", "muted", job.id));
      tr.appendChild(el("td", null, job.key));
      const tdStatus = el("td");
      tdStatus.appendChild(statusPill(job.status));
      tr.appendChild(tdStatus);
      tr.appendChild(el("td", null, job.attempts));
      tr.appendChild(el("td", "muted", job.lease_runner_id));
      jobsBody.appendChild(tr);
    }
  }

  async function refresh() {
    try {
      const runs = await api("/api/v1/runs");
      setConn(true);
      showError("");
      renderRuns(runs);
      if (state.selectedRun) selectRun(state.selectedRun);
    } catch (err) {
      setConn(false);
      if (String(err.message).indexOf("401") >= 0) setSignedOut();
    }
  }

  $("#refresh").addEventListener("click", refresh);

  refresh();
  setInterval(refresh, POLL_MS);
})();

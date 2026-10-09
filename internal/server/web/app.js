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
  const state = {
    csrf: "",
    authed: false,
    selectedRun: null,
    nextCursor: "",
    loadedRuns: [],
    paged: false,
    // Monotonic request epochs: every fetch captures the value it observed
    // and must re-check it before rendering. A slow response for run A can
    // never repaint the pane after the user selected run B, and an older
    // newest-page refresh can never overwrite a newer one.
    runsEpoch: 0,
    jobsEpoch: 0,
    // jobsAbort cancels the in-flight jobs fetch when the selection changes
    // (belt and braces on top of the epoch guard).
    jobsAbort: null,
  };

  const $ = (sel) => document.querySelector(sel);
  const conn = $("#conn");
  const loginForm = $("#login");
  const logoutBtn = $("#logout");
  const statsEl = $("#stats");
  const runsTable = $("#runs");
  const runsBody = $("#runs tbody");
  const jobsBody = $("#jobs tbody");
  const detail = $("#detail");
  const errorEl = $("#error");
  const pausedEl = $("#paused");
  const runNote = $("#run-note");

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

  // setPaged toggles history mode. While older pages are on screen the runs
  // table must not be replaced by auto-refresh, so the toolbar explicitly
  // says live updates are paused instead of freezing silently.
  function setPaged(paged) {
    state.paged = !!paged;
    pausedEl.classList.toggle("hidden", !state.paged);
  }

  function setSignedOut() {
    state.authed = false;
    state.csrf = "";
    state.selectedRun = null;
    // Invalidate every in-flight render and cancel the pending jobs fetch:
    // the signed-out UI must not be repainted by a response to a request
    // issued while a session existed.
    state.runsEpoch++;
    state.jobsEpoch++;
    if (state.jobsAbort) {
      state.jobsAbort.abort();
      state.jobsAbort = null;
    }
    setPaged(false);
    state.loadedRuns = [];
    setNextCursor("");
    loginForm.classList.remove("hidden");
    logoutBtn.classList.add("hidden");
    detail.classList.add("hidden");
    runNote.classList.add("hidden");
    runNote.textContent = "";
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
      // POST, never GET: logout clears the session cookie server-side and
      // therefore counts as a mutation. api() attaches the double-submit
      // X-Kiwi-CSRF header from the login response like every other mutating
      // call; the server refuses a logout without it.
      await api("/api/v1/logout", { method: "POST" });
    } catch (err) {
      /* local sign-out proceeds regardless; the server cookie clears only on a valid CSRF token */
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
    // While paged the stats cover the loaded history, not the newest page:
    // label the population explicitly so "loaded runs" cannot be mistaken
    // for a live total.
    const rows = [
      [state.paged ? "loaded runs" : "runs", counts.total],
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

  // runRow renders one run exactly as before: createElement/textContent only.
  function runRow(run) {
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
    return tr;
  }

  function appendRuns(runs) {
    for (const run of runs) runsBody.appendChild(runRow(run));
  }

  function renderRuns(runs) {
    renderStats(runs);
    runsBody.replaceChildren();
    appendRuns(runs);
  }

  function isTerminal(status) {
    return ["success", "failure", "cancelled", "skipped", "blocked"].indexOf(status) >= 0;
  }

  // The "Load older runs" control appends exactly one keyset page per click.
  // The next page is fetched with the opaque X-Kiwi-Next-Cursor value from the
  // previous response; the control hides on the page that reports no further
  // rows. It never walks pages on its own.
  const loadOlderBtn = el("button", "load-older hidden", "Load older runs");
  loadOlderBtn.addEventListener("click", loadOlderRuns);
  runsTable.parentNode.insertBefore(loadOlderBtn, runsTable.nextSibling);

  function setNextCursor(cursor) {
    state.nextCursor = cursor || "";
    loadOlderBtn.classList.toggle("hidden", !state.nextCursor);
  }

  // runsPage returns one collection page: its parsed run array plus the next
  // cursor header, which is absent exactly on the last page.
  async function runsPage(cursor) {
    const path = cursor
      ? "/api/v1/runs?cursor=" + encodeURIComponent(cursor)
      : "/api/v1/runs";
    const resp = await fetch(path, { credentials: "same-origin" });
    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      throw new Error(resp.status + " " + (text || resp.statusText));
    }
    return {
      runs: await resp.json(),
      nextCursor: resp.headers.get("X-Kiwi-Next-Cursor") || "",
    };
  }

  async function loadOlderRuns() {
    if (!state.nextCursor || loadOlderBtn.disabled) return;
    const cursor = state.nextCursor;
    const epoch = state.runsEpoch;
    loadOlderBtn.disabled = true;
    try {
      const page = await runsPage(cursor);
      // A newest-page refresh (manual or periodic) may have replaced the
      // table while this page was in flight; appending then would splice
      // history rows into the newest page.
      if (epoch !== state.runsEpoch) return;
      setConn(true);
      showError("");
      // Appending preserves the collection's newest-first order, and the stats
      // cover every loaded run. Auto-refresh pauses while older pages are
      // shown (see the interval below), so this page is not replaced under the
      // reader; Refresh returns to the newest page explicitly.
      setPaged(true);
      state.loadedRuns = state.loadedRuns.concat(page.runs);
      appendRuns(page.runs);
      renderStats(state.loadedRuns);
      setNextCursor(page.nextCursor);
    } catch (err) {
      if (epoch !== state.runsEpoch) return;
      if (String(err.message).indexOf("401") >= 0) setSignedOut();
      else showError("Could not load older runs: " + err.message);
    } finally {
      loadOlderBtn.disabled = false;
    }
  }

  async function selectRun(runID) {
    state.selectedRun = runID;
    // A new selection supersedes every in-flight jobs fetch: bump the epoch
    // and abort the previous request so a slow response for the previous run
    // can neither render nor surface its error over the current pane.
    const epoch = ++state.jobsEpoch;
    if (state.jobsAbort) state.jobsAbort.abort();
    const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
    state.jobsAbort = controller;
    detail.classList.remove("hidden");
    runNote.classList.add("hidden");
    runNote.textContent = "";
    jobsBody.replaceChildren(el("tr", null, "loading"));
    try {
      const options = controller ? { signal: controller.signal } : undefined;
      const jobs = await api("/api/v1/runs/" + encodeURIComponent(runID) + "/jobs", options);
      if (epoch !== state.jobsEpoch || state.selectedRun !== runID) return; // stale response discarded
      renderJobs(jobs);
    } catch (err) {
      if (epoch !== state.jobsEpoch || state.selectedRun !== runID) return; // stale failure discarded
      jobsBody.replaceChildren();
      showError("Could not load jobs: " + err.message);
    } finally {
      if (state.jobsAbort === controller) state.jobsAbort = null;
    }
  }

  // refreshSelectedQuiet is the paged-mode live path: it keeps the SELECTED
  // run's jobs pane current without touching the runs table (no
  // replaceChildren while history is on screen). A transient failure leaves
  // the pane as-is; only a vanished run (404) surfaces, as a small note.
  async function refreshSelectedQuiet() {
    const runID = state.selectedRun;
    if (!runID) return;
    const epoch = state.jobsEpoch;
    try {
      const jobs = await api("/api/v1/runs/" + encodeURIComponent(runID) + "/jobs");
      if (epoch !== state.jobsEpoch || state.selectedRun !== runID) return; // selection changed mid-flight
      runNote.classList.add("hidden");
      runNote.textContent = "";
      renderJobs(jobs);
      setConn(true);
    } catch (err) {
      if (epoch !== state.jobsEpoch || state.selectedRun !== runID) return;
      if (String(err.message).indexOf("404") >= 0) {
        runNote.textContent = "run unavailable";
        runNote.classList.remove("hidden");
      }
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
    // Only the newest refresh may render: a periodic tick and a manual click
    // can overlap, and an older response finishing last must not regress the
    // table (and the next cursor/page state) to stale data.
    const epoch = ++state.runsEpoch;
    try {
      const page = await runsPage("");
      if (epoch !== state.runsEpoch) return; // superseded by a newer refresh
      setConn(true);
      showError("");
      setPaged(false);
      state.loadedRuns = page.runs;
      renderRuns(page.runs);
      setNextCursor(page.nextCursor);
      if (state.selectedRun) selectRun(state.selectedRun);
    } catch (err) {
      if (epoch !== state.runsEpoch) return;
      setConn(false);
      if (String(err.message).indexOf("401") >= 0) setSignedOut();
    }
  }

  $("#refresh").addEventListener("click", refresh);

  refresh();
  setInterval(() => {
    // Auto-refresh keeps the newest page current until the reader loads older
    // runs: then the table is left alone so the appended pages survive, and
    // the selected run's jobs pane keeps refreshing through the quiet path.
    if (state.paged) {
      refreshSelectedQuiet();
      return;
    }
    refresh();
  }, POLL_MS);
})();

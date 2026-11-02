(() => {
  "use strict";
  const page = document.body.dataset.page;
  const $ = (id) => document.getElementById(id);
  let chart;
  const csrf = document.querySelector('meta[name="asrms-csrf"]')?.content || "";
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
  const severityClass = (severity) => String(severity || "low").toLowerCase();
  const fmtTime = (value) => value ? new Date(value).toLocaleString() : "—";

  async function getJson(url, options = {}) {
    const response = await fetch(url, {
      credentials: "same-origin",
      ...options,
      headers: {
        "Content-Type": "application/json",
        "X-ASRMS-CSRF": csrf,
        ...(options.headers || {})
      }
    });
    let body;
    try { body = await response.json(); }
    catch { body = { error: `Request failed (${response.status}); response was not JSON.` }; }
    if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
    return body;
  }

  function setStatus(message, kind = "info") {
    const banner = $("operationStatus") || $("statusBanner");
    if (!banner) return;
    banner.hidden = false;
    banner.textContent = message;
    banner.classList.toggle("warning", kind === "warning" || kind === "error");
    banner.classList.toggle("success", kind === "success");
  }

  function toast(message, title = "ASRMS") {
    const host = $("toastContainer");
    if (!host) return;
    const el = document.createElement("div");
    el.className = "toast show";
    el.innerHTML = `<div class="toast-header"><strong class="me-auto">${esc(title)}</strong><button class="btn-close btn-close-white ms-2" aria-label="Close"></button></div><div class="toast-body">${esc(message)}</div>`;
    host.appendChild(el);
    el.querySelector("button").onclick = () => el.remove();
    setTimeout(() => el.remove(), 6000);
  }

  function allPorts(scan) {
    return scan ? [...(scan.tcp || []), ...(scan.udp || [])] : [];
  }

  function processFor(processes, protocol, port) {
    return (processes || [])
      .filter((item) => item.protocol === protocol && item.port === port)
      .flatMap((item) => (item.processes || []).map((proc) => `${proc.name} (${proc.pid ?? "PID unavailable"})`))
      .join(", ") || "—";
  }

  function renderScan(scan) {
    const rows = allPorts(scan);
    const tbody = $("scanTable");
    if (!tbody) return;
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No scan results available.</td></tr>';
      return;
    }
    const states = { open: 0, closed: 0, filtered: 0, openFiltered: 0 };
    rows.forEach((row) => {
      if (row.state === "open") states.open++;
      else if (row.state === "closed") states.closed++;
      else if (row.state === "filtered") states.filtered++;
      else if (row.state === "open|filtered") states.openFiltered++;
    });
    if ($("openStateCount")) $("openStateCount").textContent = states.open;
    if ($("closedStateCount")) $("closedStateCount").textContent = states.closed;
    if ($("filteredStateCount")) $("filteredStateCount").textContent = states.filtered;
    if ($("openFilteredStateCount")) $("openFilteredStateCount").textContent = states.openFiltered;
    if ($("scanScopeLabel")) {
      const scope = scan.scope || {};
      $("scanScopeLabel").textContent = scope.ports?.length
        ? `127.0.0.1 · ${scope.ports.length} PORTS${scope.service_detection ? " · -sV" : ""}`
        : "LEGACY SCOPE UNKNOWN";
    }
    tbody.innerHTML = rows.map((row) => {
      const identification = row.identification || {};
      const serviceLabel = [
        row.service,
        row.product,
        row.version,
        row.extra_info
      ].filter(Boolean).join(" ");
      const sourceLabel = identification.source === "version-probe"
        ? "Nmap probe"
        : identification.source === "port-database"
          ? "Port database hint"
          : "Unidentified";
      const service = `${esc(serviceLabel || "unknown")}<small class="table-subtext">${sourceLabel}</small>`;
      return `<tr><td>${esc(row.protocol)}</td><td>${row.port}</td><td><span class="state-badge ${row.state === "open" ? "state-open" : row.state === "closed" ? "state-closed" : ""}">${esc(row.state)}</span></td><td>${service}</td><td>${esc(identification.confidence_label || "unknown")}${identification.confidence !== undefined ? ` (${esc(identification.confidence)}/10)` : ""}</td><td>${esc(row.reason || "—")}</td><td>${esc(processFor(scan.processes, row.protocol, row.port))}</td></tr>`;
    }).join("");
  }

  function renderProcesses(inventory) {
    const body = $("processTable");
    if (!body) return;
    if (inventory?.status === "stale") {
      body.innerHTML = `<tr><td colspan="6" class="empty-state">Listener inventory from scan #${esc(inventory.scan_id)} is stale and is not shown as current. ${esc(inventory.error || "Run a complete assessment.")}</td></tr>`;
      return;
    }
    if (inventory?.status === "error" || inventory?.status === "unavailable" || inventory?.status === "legacy_scope_unknown") {
      body.innerHTML = `<tr><td colspan="6" class="empty-state">${esc(inventory.error || "Listener inventory is unavailable.")}</td></tr>`;
      return;
    }
    const listeners = inventory?.listeners || [];
    const rows = listeners.flatMap((item) => {
      const procs = item.processes || [];
      if (!procs.length) {
        return [`<tr><td>${esc(item.protocol)}</td><td>${esc(item.local_address || "—")}</td><td>${item.port}</td><td>—</td><td>Unavailable</td><td>Permission may be required</td></tr>`];
      }
      return procs.map((proc) => `<tr><td>${esc(item.protocol)}</td><td>${esc(item.local_address || "—")}</td><td>${item.port}</td><td>${esc(proc.pid ?? "—")}</td><td>${esc(proc.name)}</td><td class="text-break">${esc(proc.exe)}</td></tr>`);
    });
    body.innerHTML = rows.length
      ? rows.join("")
      : '<tr><td colspan="6" class="empty-state">No listening sockets were found in this verified inventory.</td></tr>';
  }

  function renderRisks(risk, stale = false, scanId = null) {
    const findings = risk?.findings || [];
    const table = $("riskTable");
    if (table) {
      table.innerHTML = stale
        ? `<tr><td colspan="7" class="empty-state">Findings from scan #${esc(scanId)} are stale and are not displayed as current. Run a complete assessment.</td></tr>`
        : findings.length ? findings.map((item) => `<tr><td><span class="severity ${severityClass(item.severity)}">${esc(item.severity)}</span></td><td>${esc(item.protocol)}/${item.port}</td><td>${esc(item.service)}</td><td>${item.firewall_restricted ? '<span class="state-badge state-closed">LIVE RULE VERIFIED</span>' : '<span class="state-badge state-open">EXPOSED</span>'}</td><td>${esc(item.service_state || "unknown")}<small class="table-subtext">${item.listeners?.length ? esc(item.listeners.map((listener) => listener.local_address).join(", ")) : "No matching listener mapped"}</small></td><td>${esc(item.recommendation)}</td><td>${item.firewall_restricted ? "—" : `<button class="btn btn-sm btn-outline-light restrict-button" data-protocol="${esc(item.protocol)}" data-port="${item.port}">Restrict</button>`}</td></tr>`).join("") : '<tr><td colspan="7" class="empty-state">No open ports in the latest assessment. This is not a vulnerability guarantee.</td></tr>';
    }
    const summary = $("riskSummary");
    if (summary) {
      const items = [["Critical", risk?.critical || 0, "#ff6677"], ["High", risk?.high || 0, "#ffb454"], ["Medium", risk?.medium || 0, "#e5cb64"], ["Low", risk?.low || 0, "#41d7d1"]];
      const max = Math.max(1, ...items.map((item) => item[1]));
      summary.innerHTML = stale
        ? `<div class="empty-state">Risk distribution from scan #${esc(scanId)} is stale.</div>`
        : items.map(([name, count, color]) => `<div class="risk-row"><span class="risk-name">${name}</span><div class="risk-track"><span style="width:${count / max * 100}%;background:${color}"></span></div><span class="risk-number">${count}</span></div>`).join("");
    }
    const priority = $("findingsTable");
    if (priority) {
      priority.innerHTML = stale
        ? `<tr><td colspan="5" class="empty-state">Findings from scan #${esc(scanId)} are stale and are not displayed as current.</td></tr>`
        : findings.length
          ? findings.map((item) => `<tr><td>${esc(item.protocol)}/${item.port}</td><td>${esc(item.service)}</td><td><span class="severity ${severityClass(item.severity)}">${esc(item.severity)}</span></td><td>${item.firewall_restricted ? "Restricted" : "Exposed"}</td><td>${esc(item.recommendation)}</td></tr>`).join("")
          : '<tr><td colspan="5" class="empty-state">No open ports in the latest assessment.</td></tr>';
    }
    if (!stale) {
      document.querySelectorAll(".restrict-button").forEach((button) => button.addEventListener("click", () => confirmRestriction(button.dataset.protocol, Number(button.dataset.port))));
    }
  }

  function renderOverview(scan, rules, stale) {
    if (!scan) return;
    const risk = scan.risk || {};
    if ($("scoreValue")) $("scoreValue").textContent = risk.score ?? "--";
    if ($("scoreBar")) $("scoreBar").style.width = `${risk.score ?? 0}%`;
    if ($("scoreLabel")) $("scoreLabel").textContent = stale ? "Last verified (stale)" : risk.score >= 80 ? "Good" : risk.score >= 60 ? "Needs attention" : "Action recommended";
    if ($("exposedCount")) $("exposedCount").textContent = risk.exposed_ports ?? 0;
    if ($("highRiskCount")) $("highRiskCount").textContent = (risk.critical || 0) + (risk.high || 0);
    if ($("firewallCount")) $("firewallCount").textContent = rules.filter((item) => item.verified && item.enabled && !item.removed_at).length;
    renderRisks(risk, stale, scan.id);
    const banner = $("statusBanner");
    if (banner) {
      const stale = scan.status === "stale";
      banner.textContent = stale
        ? `Assessment is stale; last verified data retained. ${scan.error || ""} · Scan #${scan.id} · ${fmtTime(scan.created_at)}`
        : scan.status === "legacy_scope_unknown"
          ? `Legacy scan #${scan.id} has no recorded scope and is not eligible for comparisons. Run a new complete assessment.`
          : `Latest complete assessment · ${fmtTime(scan.created_at)} · Scan #${scan.id} · ${scan.scope?.ports?.length || 0} ports`;
      banner.classList.toggle("warning", stale || scan.status === "legacy_scope_unknown");
    }
    const canvas = $("exposureChart");
    const empty = $("chartEmpty");
    if (canvas && window.Chart) {
      const counts = { Open: 0, Closed: 0, Filtered: 0, "Open|filtered": 0 };
      allPorts(scan).forEach((item) => {
        const key = item.state === "open|filtered" ? "Open|filtered" : item.state[0]?.toUpperCase() + item.state.slice(1);
        if (key in counts) counts[key]++;
      });
      if (empty) empty.style.display = allPorts(scan).length ? "none" : "grid";
      if (chart) chart.destroy();
      chart = new Chart(canvas, {
        type: "bar",
        data: { labels: Object.keys(counts), datasets: [{ data: Object.values(counts), backgroundColor: ["#41d7d1", "#4fd6a0", "#ffb454", "#9d83ff"], borderRadius: 5, maxBarThickness: 45 }] },
        options: { maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { grid: { display: false }, ticks: { color: "#8796aa" } }, y: { beginAtZero: true, ticks: { precision: 0, color: "#8796aa" }, grid: { color: "#202d40" } } } }
      });
    }
    renderScan(scan);
    renderHistory(window.asrmsHistory || []);
  }

  function renderRules(rules) {
    const body = $("firewallTable");
    if (!body) return;
    const visibleRules = rules.filter((rule) => !rule.removed_at || !rule.recorded);
    body.innerHTML = visibleRules.length ? visibleRules.map((rule) => {
      const actual = rule.observed_rule || {};
      const verdict = rule.verified
        ? '<span class="state-badge state-closed">VERIFIED CONFIG</span>'
        : rule.recorded
          ? '<span class="state-badge state-open">UNVERIFIED / MISSING</span>'
          : '<span class="state-badge">EXTERNAL RULE</span>';
      const rollback = rule.rollback_allowed && rule.id
        ? `<button class="btn btn-sm btn-outline-light rollback-button" data-id="${rule.id}">Rollback</button>`
        : "—";
      return `<tr><td>${esc(rule.rule_name)}</td><td>${esc(rule.protocol)}</td><td>${esc(rule.port)}</td><td>${rule.enabled ? "Yes" : "No"}</td><td>${esc(actual.direction || "—")} / ${esc(actual.action || "—")}</td><td>${verdict}</td><td>${rollback}</td></tr>`;
    }).join("") : '<tr><td colspan="7" class="empty-state">No inbound block rules.</td></tr>';
    document.querySelectorAll(".rollback-button").forEach((button) => button.addEventListener("click", () => rollbackRule(Number(button.dataset.id))));
  }

  function renderHistory(history) {
    const body = $("historyTable");
    if (!body) return;
    body.innerHTML = history.length ? history.map((scan) => `<tr><td>#${scan.id}</td><td>${esc(fmtTime(scan.created_at))}</td><td><span class="state-badge ${scan.status === "verified" ? "state-closed" : "state-open"}">${esc(scan.status)}</span></td><td>${esc(scan.source)}</td><td>${scan.risk?.score ?? "--"}</td><td>${scan.risk?.exposed_ports ?? "--"}</td></tr>`).join("") : '<tr><td colspan="6" class="empty-state">No scan history.</td></tr>';
  }

  function renderEvents(events, target) {
    if (!target) return;
    target.innerHTML = events.length ? events.map((event) => `<div class="event-row"><span class="event-marker ${event.category?.includes("error") ? "error" : ""}"></span><div><strong>${esc(event.message)}</strong><small>${esc(event.category)} · ${esc(fmtTime(event.created_at))}</small></div></div>`).join("") : '<div class="empty-state">No events recorded.</div>';
  }

  function renderBaselineOptions(history, selectedId) {
    const select = $("baselineSelect");
    if (!select) return;
    const previousSelection = select.value;
    const scans = history.filter((scan) => scan.complete && scan.status === "verified" && scan.scope?.ports?.length);
    select.innerHTML = scans.length
      ? scans.map((scan) => `<option value="${scan.id}">#${scan.id} · ${esc(fmtTime(scan.created_at))} · ${scan.scope.target} · ${scan.scope.protocols.join("/")} · ${scan.scope.ports.join(",")}</option>`).join("")
      : '<option value="">No complete verified scans</option>';
    const selection = scans.some((scan) => String(scan.id) === previousSelection)
      ? previousSelection
      : String(selectedId || "");
    if (selection && scans.some((scan) => String(scan.id) === selection)) select.value = selection;
  }

  function renderComparison(data, history) {
    renderBaselineOptions(history, data.baseline_id);
    const set = (id, value) => { if ($(id)) $(id).textContent = value; };
    const status = $("comparisonStatus");
    if (status) {
      status.textContent = data.compatible
        ? `Compatible scope · baseline #${data.baseline_id} at ${fmtTime(data.baseline_timestamp)} · ${data.scope.ports.length} loopback ports · ${data.scope.protocols.join("/")}`
        : data.incompatibility_reason || "A complete baseline and current assessment are required.";
      status.classList.toggle("warning", !data.compatible);
    }
    const baselineDetails = $("baselineDetails");
    if (baselineDetails) {
      baselineDetails.textContent = data.baseline
        ? `Baseline #${data.baseline_id} · ${fmtTime(data.baseline_timestamp)} · Scope: ${data.baseline.scope?.ports?.length ? `${data.baseline.scope.target}, ${data.baseline.scope.protocols.join("/")}, ports ${data.baseline.scope.ports.join(",")}` : "unknown legacy scope"}. It remains unchanged until explicitly reset.`
        : "No baseline is available. The first complete verified assessment establishes it.";
    }
    const baselineScanButton = $("scanBaselineScope");
    if (baselineScanButton) {
      const selectedScan = history.find((scan) => String(scan.id) === $("baselineSelect")?.value);
      baselineScanButton.disabled = !selectedScan?.complete || selectedScan.status !== "verified" || !selectedScan.scope?.ports?.length;
    }
    set("baselineCount", data.compatible ? data.initially_exposed.length : "—");
    set("currentCount", data.compatible ? data.currently_exposed.length : "—");
    set("restrictedCount", data.compatible ? data.restricted_ports.length : "—");
    set("scoreImprovement", !data.compatible || data.score_improvement === null ? "—" : `${data.score_improvement > 0 ? "+" : ""}${data.score_improvement}`);
    set("reductionPercent", !data.compatible || data.attack_surface_reduction_percent === null ? "Not comparable" : `${data.attack_surface_reduction_percent}%`);
    const tags = (id, items) => { if ($(id)) $(id).innerHTML = items?.length ? items.map((item) => `<span class="port-tag">${esc(typeof item === "string" ? item : `${item.protocol}/${item.port} ${item.severity}`)}</span>`).join("") : '<span class="port-tag empty">None recorded</span>'; };
    tags("initiallyExposed", data.compatible ? data.initially_exposed : []);
    tags("currentlyExposed", data.compatible ? data.currently_exposed : []);
    tags("restrictedPorts", data.compatible ? data.restricted_ports : []);
    tags("noLongerOpen", data.compatible ? data.no_longer_observed_open : []);
    tags("remainingRisks", data.remaining_high_risk);
  }

  function renderMonitoring(value) {
    if ($("cpuValue")) $("cpuValue").textContent = value.cpu_percent ?? "--";
    if ($("cpuBar")) $("cpuBar").style.width = `${value.cpu_percent ?? 0}%`;
    if ($("memoryValue")) $("memoryValue").textContent = value.memory_percent ?? "--";
    if ($("memoryBar")) $("memoryBar").style.width = `${value.memory_percent ?? 0}%`;
    if ($("memoryUsed")) $("memoryUsed").textContent = value.memory_used_mb ?? "--";
    if ($("processCount")) $("processCount").textContent = value.process_count ?? "--";
  }

  function enableTableSearch() {
    const input = $("tableSearch");
    if (!input) return;
    input.addEventListener("input", () => {
      const query = input.value.trim().toLowerCase();
      const tables = document.querySelectorAll(".app-table tbody");
      tables.forEach((table) => table.querySelectorAll("tr").forEach((row) => {
        row.hidden = Boolean(query) && !row.textContent.toLowerCase().includes(query);
      }));
    });
  }

  function renderState(data) {
    window.asrmsHistory = data.history || [];
    const scan = data.latest_scan;
    const stale = data.assessment_status === "stale" || scan?.status === "stale";
    if (scan) renderOverview(scan, data.firewall_rules || [], stale);
    else if (data.assessment_status === "stale") {
      setStatus(`Assessment stale: ${data.assessment_error || data.error || "verification failed"}`, "error");
    }
    renderProcesses(data.process_inventory || {
      status: "unavailable",
      error: "Run a complete assessment to collect listener data.",
      listeners: []
    });
    renderRules(data.firewall_rules || []);
    renderHistory(data.history || []);
    renderEvents(data.events || [], $("eventsList"));
    renderEvents(data.events || [], $("auditList"));
    renderMonitoring(data.monitoring || {});
    if ($("operationStatus") && data.assessment_status === "stale") {
      setStatus(`Assessment stale: ${data.assessment_error || "live state changed; run a complete scan."}`, "error");
    }
    if ($("lastUpdated")) $("lastUpdated").textContent = `Updated ${new Date().toLocaleTimeString()}`;
    if (page === "comparison" && data.comparison) renderComparison(data.comparison, data.history || []);
    if (page === "firewall" && $("adminStatus")) {
      $("adminStatus").textContent = data.administrator ? "Administrator access" : "Administrator required";
    }
  }

  async function refresh() {
    try {
      renderState(await getJson("/api/state"));
      return { ok: true };
    } catch (error) {
      console.error(error);
      if ($("lastUpdated")) $("lastUpdated").textContent = "Verification unavailable";
      renderRisks({}, true, "unknown");
      renderProcesses({
        status: "stale",
        error: "Live verification failed; retained listener rows are not shown as current.",
        scan_id: "unknown"
      });
      setStatus(`Live verification failed; previous assessment must be treated as stale. ${error.message}`, "error");
      return { ok: false, error };
    }
  }

  async function runScan(button) {
    const input = $("portsInput");
    const ports = input ? input.value.split(",").map((value) => Number(value.trim())) : undefined;
    if (input && (ports.some((value) => !Number.isInteger(value) || value < 1 || value > 65535) || ports.length > 100 || new Set(ports).size !== ports.length)) {
      toast("Enter up to 100 unique comma-separated port numbers between 1 and 65535.", "Invalid ports");
      return;
    }
    const serviceDetection = Boolean($("serviceDetection")?.checked);
    button.disabled = true;
    const originalText = button.textContent;
    button.textContent = "Scanning TCP + UDP…";
    setStatus("Scanning 127.0.0.1 over TCP and UDP; refreshing listeners and firewall configuration…");
    try {
      const result = await getJson("/api/scans", {
        method: "POST",
        body: JSON.stringify({ ...(ports ? { ports } : {}), service_detection: serviceDetection })
      });
      const sync = await refresh();
      setStatus(
        sync.ok
          ? `Assessment #${result.id} verified · ${result.scope.ports.length} ports · all dashboard data refreshed. Remote reachability was not tested.`
          : `Assessment #${result.id} verified, but dashboard synchronization failed: ${sync.error.message}`,
        sync.ok ? "success" : "warning"
      );
    } catch (error) {
      await refresh();
      setStatus(`Assessment failed; prior data is retained and marked stale. ${error.message}`, "error");
    } finally {
      button.disabled = false;
      button.textContent = originalText;
    }
  }

  async function confirmRestriction(protocol, port) {
    const ok = window.confirm(`Create and verify an inbound Windows Firewall BLOCK rule for ${protocol}/${port}?\n\nThis limits inbound traffic; it does not stop the listening service. A complete TCP/UDP scan over the previous assessment scope will run afterward. Administrator access is required.`);
    if (!ok) return;
    setStatus(`Applying and verifying inbound ${protocol}/${port} restriction, then rescanning the complete previous scope…`);
    try {
      const result = await getJson("/api/firewall/rules", { method: "POST", body: JSON.stringify({ protocol, port, confirmed: true }) });
      const sync = await refresh();
      setStatus(
        sync.ok
          ? `Restriction verified for ${protocol}/${port} · complete scan #${result.scan.id} · assessment and dashboard synchronized.`
          : `Restriction and scan #${result.scan.id} were verified, but dashboard synchronization failed: ${sync.error.message}`,
        sync.ok ? "success" : "warning"
      );
    } catch (error) {
      await refresh();
      setStatus(error.message, "error");
    }
  }

  async function rollbackRule(id) {
    if (!window.confirm("Remove this identified application-created firewall rule and verify rollback with a complete TCP/UDP rescan?")) return;
    setStatus("Verifying rule identity, rolling back, and rescanning the complete previous scope…");
    try {
      const result = await getJson(`/api/firewall/rules/${id}`, { method: "DELETE", body: JSON.stringify({ confirmed: true }) });
      const sync = await refresh();
      setStatus(
        sync.ok
          ? `Rollback and complete scan #${result.scan.id} verified · assessment and dashboard synchronized.`
          : `Rollback and scan #${result.scan.id} were verified, but dashboard synchronization failed: ${sync.error.message}`,
        sync.ok ? "success" : "warning"
      );
    } catch (error) {
      await refresh();
      setStatus(error.message, "error");
    }
  }

  const baselineScanButton = $("scanBaselineScope");
  if (baselineScanButton) baselineScanButton.addEventListener("click", async () => {
    const scanId = Number($("baselineSelect")?.value);
    if (!scanId || !window.confirm(`Run a complete TCP/UDP assessment using scan #${scanId}'s exact loopback target, protocols, and ports?`)) return;
    baselineScanButton.disabled = true;
    setStatus(`Scanning the exact scope recorded in baseline #${scanId}…`);
    try {
      const result = await getJson("/api/comparison/scan-baseline", {
        method: "POST",
        body: JSON.stringify({ scan_id: scanId })
      });
      const sync = await refresh();
      setStatus(
        sync.ok
          ? `Baseline scope assessment #${result.latest_assessment_id} verified · comparison scope synchronized.`
          : `Assessment #${result.latest_assessment_id} verified, but dashboard synchronization failed: ${sync.error.message}`,
        sync.ok ? "success" : "warning"
      );
    } catch (error) {
      await refresh();
      setStatus(error.message, "error");
    } finally {
      baselineScanButton.disabled = false;
    }
  });

  const baselineButton = $("setBaseline");
  if (baselineButton) baselineButton.addEventListener("click", async () => {
    const select = $("baselineSelect");
    const scanId = Number(select?.value);
    if (!scanId || !window.confirm(`Set scan #${scanId} as the new comparison baseline? This explicitly replaces the existing baseline.`)) return;
    try {
      const result = await getJson("/api/comparison/baseline", {
        method: "POST",
        body: JSON.stringify({ scan_id: scanId })
      });
      toast(`Baseline set to scan #${result.baseline_id}.`, "Baseline updated");
      await refresh();
    } catch (error) {
      toast(error.message, "Baseline unchanged");
    }
  });

  document.querySelectorAll("[data-scan]").forEach((button) => button.addEventListener("click", () => runScan(button)));
  const form = $("firewallForm");
  if (form) form.addEventListener("submit", (event) => {
    event.preventDefault();
    confirmRestriction($("ruleProtocol").value, Number($("rulePort").value));
  });
  const menuToggle = $("menuToggle");
  if (menuToggle) menuToggle.addEventListener("click", () => $("sidebar").classList.toggle("open"));
  enableTableSearch();
  refresh();
  setInterval(refresh, 5000);
})();

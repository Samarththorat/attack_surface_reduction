(() => {
  "use strict";
  const page = document.body.dataset.page;
  const $ = (id) => document.getElementById(id);
  let chart;
  const csrf = document.querySelector('meta[name="asrms-csrf"]')?.content || "";
  let analyzedUrlToOpen = null;
  let isAdministrator = false;
  let securityNotifications = [];
  const reportDownloads = new Set();
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

  function reportFilename(response, fallback) {
    const disposition = response.headers.get("Content-Disposition") || "";
    const encoded = disposition.match(/filename\*\s*=\s*UTF-8''([^;]+)/i);
    const regular = disposition.match(/filename\s*=\s*(?:"([^"]+)"|([^;]+))/i);
    let filename = fallback;
    if (encoded) {
      try { filename = decodeURIComponent(encoded[1]); }
      catch { filename = encoded[1]; }
    } else if (regular) {
      filename = (regular[1] || regular[2]).trim();
    }
    return filename
      .split(/[\\/]/)
      .pop()
      .replace(/[<>:"|?*\x00-\x1f]/g, "_") || fallback;
  }

  function bindReportDownloads() {
    document.querySelectorAll("[data-report-download]").forEach((link) => {
      link.addEventListener("click", async (event) => {
        event.preventDefault();
        const format = link.dataset.reportDownload;
        const expectedTypes = {
          pdf: "application/pdf",
          excel: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        };
        const expectedType = expectedTypes[format];
        const endpoint = new URL(link.href, window.location.href);
        const downloadKey = endpoint.href;
        if (reportDownloads.has(downloadKey) || link.getAttribute("aria-disabled") === "true") return;
        reportDownloads.add(downloadKey);
        const matchingLinks = [...document.querySelectorAll("[data-report-download]")]
          .filter((item) => item.href === downloadKey);
        matchingLinks.forEach((item) => {
          item.setAttribute("aria-disabled", "true");
          item.setAttribute("aria-busy", "true");
          item.classList.add("disabled");
        });
        setStatus(`Preparing ${format.toUpperCase()} report…`);
        try {
          if (!expectedType || endpoint.origin !== window.location.origin ||
              endpoint.pathname !== `/api/reports/${format}`) {
            throw new Error("Invalid report download link.");
          }
          const response = await fetch(endpoint.href, { credentials: "same-origin" });
          if (!response.ok) {
            const body = await response.json().catch(() => ({}));
            throw new Error(body.error || `Report download failed (${response.status}).`);
          }
          const contentType = (response.headers.get("Content-Type") || "").split(";")[0].trim().toLowerCase();
          if (contentType !== expectedType) {
            throw new Error(`The server returned an unexpected report type: ${contentType || "unknown"}.`);
          }
          const blob = await response.blob();
          if (!blob.size) throw new Error("The generated report is empty.");
          const filename = reportFilename(response, `asrms-security-report.${format === "excel" ? "xlsx" : "pdf"}`);
          const objectUrl = URL.createObjectURL(blob);
          const downloadLink = document.createElement("a");
          downloadLink.href = objectUrl;
          downloadLink.download = filename;
          downloadLink.hidden = true;
          document.body.appendChild(downloadLink);
          try { downloadLink.click(); }
          finally {
            downloadLink.remove();
            window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
          }
          setStatus(`Report download started: ${filename}.`, "success");
        } catch (error) {
          setStatus(`Could not download report: ${error.message}`, "error");
        } finally {
          reportDownloads.delete(downloadKey);
          matchingLinks.forEach((item) => {
            item.removeAttribute("aria-disabled");
            item.removeAttribute("aria-busy");
            item.classList.remove("disabled");
          });
        }
      });
    });
  }

  function allPorts(scan) {
    return scan ? [...(scan.tcp || []), ...(scan.udp || [])] : [];
  }

  function processFor(processes, protocol, port) {
    const processNames = (processes || [])
      .filter((item) => item.protocol === protocol && item.port === port)
      .flatMap((item) => (item.processes || []).map((proc) => `${proc.name} (${proc.pid ?? "PID unavailable"})`));
    return [...new Set(processNames)].join(", ") || "—";
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
        : findings.length ? findings.map((item) => {
          const firewallFinding = item.protocol === "FIREWALL";
          const subject = firewallFinding ? "Windows Firewall profiles" : `${item.protocol}/${item.port}`;
          const status = firewallFinding ? "PROFILE HEALTH" : item.firewall_restricted ? "LIVE RULE VERIFIED" : "EXPOSED";
          return `<tr><td><span class="severity ${severityClass(item.severity)}">${esc(item.severity)}</span></td><td>${esc(subject)}</td><td>${esc(item.service)}</td><td>${item.firewall_restricted ? '<span class="state-badge state-closed">LIVE RULE VERIFIED</span>' : `<span class="state-badge ${firewallFinding ? "state-open" : "state-open"}">${status}</span>`}</td><td>${esc(item.service_state || "unknown")}<small class="table-subtext">${item.listeners?.length ? esc(item.listeners.map((listener) => listener.local_address).join(", ")) : firewallFinding ? esc((item.profiles || []).join(", ") || "Profile verification") : "No matching listener mapped"}</small></td><td>${esc(item.recommendation)}</td><td>${firewallFinding || item.firewall_restricted ? "—" : `<button class="btn btn-sm btn-outline-light restrict-button" data-protocol="${esc(item.protocol)}" data-port="${item.port}">Restrict</button>`}</td></tr>`;
        }).join("") : '<tr><td colspan="7" class="empty-state">No open ports in the latest assessment. This is not a vulnerability guarantee.</td></tr>';
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

  function renderRiskUrlContext(observations) {
    const target = $("urlRiskContext");
    if (!target) return;
    const scans = observations?.scans || [];
    target.innerHTML = scans.length ? scans.slice(0, 10).map((item) => `<div class="event-row"><span class="event-marker"></span><div><strong>Scan #${esc(item.scan_id)} · ${esc(item.destination_type)} · ${esc(item.risk_level)} heuristic risk (${esc(item.risk_score)}/100)</strong><small>${esc(fmtTime(item.created_at))} · Reputation ${esc(item.reputation_status)} · ${esc(item.findings.join(", ") || "No indicators")}</small><p>${esc(item.submitted_url)}</p><p><strong>Scoring:</strong> Not deducted from host exposure. ${esc(observations.reason || "URL reputation remains unverified.")}</p></div></div>`).join("") : '<div class="empty-state">No recent URL assessments.</div>';
  }

  function renderOverview(scan, rules, stale, firewallProfiles, portMonitoring) {
    if (!scan) return;
    const risk = scan.risk || {};
    if ($("scoreValue")) $("scoreValue").textContent = risk.score ?? "--";
    if ($("scoreBar")) $("scoreBar").style.width = `${risk.score ?? 0}%`;
    if ($("scoreLabel")) $("scoreLabel").textContent = risk.score === null || risk.score === undefined ? "Assessment incomplete" : stale ? "Last verified (stale)" : risk.score >= 80 ? "Good" : risk.score >= 60 ? "Needs attention" : "Action recommended";
    if ($("exposedCount")) $("exposedCount").textContent = risk.exposed_ports ?? 0;
    if ($("highRiskCount")) $("highRiskCount").textContent = (risk.critical || 0) + (risk.high || 0);
    if ($("firewallCount")) $("firewallCount").textContent = rules.filter((item) => item.verified && item.enabled && !item.removed_at).length;
    renderFirewallProfiles(firewallProfiles, risk.firewall_health);
    if ($("activeListenerCount")) $("activeListenerCount").textContent = portMonitoring?.summary?.tcp_listeners ?? "--";
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
    const tags = (id, items) => { if ($(id)) $(id).innerHTML = items?.length ? items.map((item) => `<span class="port-tag">${esc(typeof item === "string" ? item : item.protocol === "FIREWALL" ? `${item.service} ${item.severity}` : `${item.protocol}/${item.port} ${item.severity}`)}</span>`).join("") : '<span class="port-tag empty">None recorded</span>'; };
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

  function renderFirewallProfiles(value, health) {
    const profiles = value?.profiles || [];
    const known = value?.collection_status === "verified" && profiles.length === 3;
    const effectiveHealth = known ? (health?.status || value?.health?.status || "Unknown") : "Unknown";
    const summary = $("firewallProfileSummary");
    if (summary) {
      summary.textContent = known
        ? profiles.map((item) => `${item.name}: ${item.enabled ? "Enabled" : "Disabled"}`).join(" · ")
        : `Unknown · ${value?.error || "Live firewall profile status is unavailable."}`;
    }
    const policy = $("firewallPolicySummary");
    if (policy) {
      policy.textContent = known
        ? `Default inbound: ${profiles.map((item) => `${item.name} ${item.default_inbound_action}`).join(" · ")} | Default outbound: ${profiles.map((item) => `${item.name} ${item.default_outbound_action}`).join(" · ")} | Last verified: ${fmtTime(value.verified_at)}`
        : `Collection status: ${value?.collection_status || "unavailable"} · ${value?.error || "Protection is not assumed."}`;
    }
    if ($("firewallHealthValue")) $("firewallHealthValue").textContent = effectiveHealth;
    if ($("firewallProfilesNote")) {
      $("firewallProfilesNote").textContent = known
        ? `${health?.enabled_count ?? value?.health?.enabled_count ?? profiles.filter((item) => item.enabled).length}/3 profiles enabled`
        : "Live profiles not verified";
    }
    if ($("firewallHealthBadge")) {
      $("firewallHealthBadge").textContent = effectiveHealth;
      $("firewallHealthBadge").className = `state-badge ${effectiveHealth === "Healthy" ? "state-closed" : "state-open"}`;
    }
    const cards = $("firewallProfileCards");
    if (cards) {
      cards.innerHTML = known ? profiles.map((item) => {
        const enabled = item.enabled === true;
        const action = enabled ? "Disable" : "Enable";
        return `<article class="profile-card"><div><strong>${esc(item.name)} profile</strong><span class="state-badge ${enabled ? "state-closed" : "state-open"}">${enabled ? "Enabled" : "Disabled"}</span></div><p>Inbound: ${esc(item.default_inbound_action)} · Outbound: ${esc(item.default_outbound_action)}</p><p>Last verified: ${esc(fmtTime(value.verified_at))}</p><button class="btn ${enabled ? "btn-danger" : "btn-primary"} profile-action" data-profile="${esc(item.name)}" data-enabled="${enabled ? "false" : "true"}" ${isAdministrator ? "" : "disabled"}>${action} Firewall</button></article>`;
      }).join("") : '<div class="empty-state">Profile controls are unavailable until live status is verified.</div>';
      cards.querySelectorAll(".profile-action").forEach((button) => button.addEventListener("click", () => changeFirewallProfile(button.dataset.profile, button.dataset.enabled === "true")));
    }
  }

  async function changeFirewallProfile(profile, enabled) {
    const explanation = enabled
      ? `Enable the ${profile} Windows Firewall profile? Windows Firewall will apply its current rules to this network profile. Administrator permissions are required; Group Policy may prevent changes.`
      : `WARNING: Disable the ${profile} Windows Firewall profile? This removes firewall filtering for this profile and can expose local services. Administrator permissions are required; Group Policy may prevent changes.`;
    if (!window.confirm(explanation)) return;
    setStatus(`${enabled ? "Enabling" : "Disabling"} ${profile} profile; verifying actual Windows Firewall state and refreshing the assessment…`);
    try {
      const result = await getJson(`/api/firewall/profiles/${encodeURIComponent(profile)}`, {
        method: "POST",
        body: JSON.stringify({ enabled, confirmed: true })
      });
      await refresh();
      const assessmentMessage = result.assessment_status === "verified"
        ? `Assessment #${result.assessment.id} refreshed.`
        : `Assessment refresh failed and is stale: ${result.assessment_error || "unknown error"}`;
      setStatus(`Windows Firewall ${profile} profile ${enabled ? "enabled" : "disabled"} and verified. ${assessmentMessage}`, result.assessment_status === "verified" ? "success" : "warning");
    } catch (error) {
      await refresh();
      setStatus(`${error.message}${error.message.toLowerCase().includes("administrator") ? " Administrator Required." : ""}`, "error");
    }
  }

  function renderSecurityNotifications(notifications) {
    securityNotifications = notifications || [];
    const target = $("securityAlerts");
    const filter = $("notificationFilter")?.value || "all";
    if (!target) return;
    const active = securityNotifications.filter((item) => !item.dismissed);
    const visible = filter === "all" ? active : active.filter((item) => String(item.severity).toLowerCase() === filter);
    target.innerHTML = visible.length ? visible.map((item) => {
      const details = item.details || {};
      const fields = [
        details.event_type,
        details.protocol ? `${details.protocol}/${details.port ?? "?"}` : null,
        details.process_name ? `${details.process_name} (PID ${details.pid ?? "unavailable"})` : null,
        details.executable
      ].filter(Boolean).map(esc).join(" · ");
      return `<article class="event-row notification-row"><span class="event-marker ${["critical", "high"].includes(String(item.severity).toLowerCase()) ? "error" : ""}"></span><div><strong><span class="severity ${severityClass(item.severity)}">${esc(item.severity)}</span> ${esc(item.message)}</strong><small>${esc(fmtTime(item.created_at))}${fields ? ` · ${fields}` : ""}</small><p>${esc(details.reason || "No additional reason was recorded.")}</p><p><strong>Recommended:</strong> ${esc(details.recommendation || "Review the detailed event history.")}</p></div><button class="btn btn-sm btn-outline-light dismiss-notification" data-id="${esc(item.id)}" aria-label="Dismiss notification">Dismiss</button></article>`;
    }).join("") : '<div class="empty-state">No active notifications match this filter.</div>';
    target.querySelectorAll(".dismiss-notification").forEach((button) => button.addEventListener("click", () => dismissNotification(button.dataset.id)));
  }

  async function dismissNotification(id) {
    try {
      await getJson(`/api/security-notifications/${encodeURIComponent(id)}/dismiss`, {
        method: "POST",
        body: JSON.stringify({ confirmed: true })
      });
      await refresh();
    } catch (error) {
      setStatus(`Could not dismiss notification: ${error.message}`, "error");
    }
  }

  function renderPortMonitoring(value) {
    const summary = value?.summary || {};
    if ($("tcpListenerCount")) $("tcpListenerCount").textContent = summary.tcp_listeners ?? "--";
    if ($("udpSocketCount")) $("udpSocketCount").textContent = summary.udp_sockets ?? "--";
    if ($("persistentListenerCount")) $("persistentListenerCount").textContent = summary.persistent_tcp_listeners ?? "--";
    if ($("recentlyClosedCount")) $("recentlyClosedCount").textContent = summary.recently_closed_tcp_listeners ?? "--";
    if ($("newTcpCount")) $("newTcpCount").textContent = summary.new_tcp_listeners ?? "--";
    if ($("newUdpCount")) $("newUdpCount").textContent = summary.new_udp_sockets ?? "--";
    if ($("removedUdpCount")) $("removedUdpCount").textContent = summary.recently_removed_udp_sockets ?? "--";
    if ($("portMonitorUpdated")) $("portMonitorUpdated").textContent = `Last updated ${fmtTime(value?.last_updated)}`;
    const status = $("portMonitorStatus");
    if (status) {
      status.textContent = value?.status === "verified"
        ? `Monitoring ${summary.tcp_listeners ?? 0} TCP listeners and ${summary.udp_sockets ?? 0} UDP sockets.`
        : `Port inventory ${value?.status || "unavailable"}. ${value?.error || "Waiting for a successful socket snapshot."}`;
      status.classList.toggle("warning", value?.status !== "verified");
    }
    const body = $("portMonitorTable");
    if (body) {
      const listeners = value?.status === "verified" ? (value.listeners || []) : [];
      body.innerHTML = value?.status !== "verified"
        ? `<tr><td colspan="11" class="empty-state">Listener inventory is ${esc(value?.status || "unavailable")}; retained socket rows are not presented as current. ${esc(value?.error || "")}</td></tr>`
        : listeners.length ? listeners.map((item) => `<tr><td>${esc(item.protocol)}</td><td>${esc(item.local_address)}</td><td>${esc(item.port)}</td><td>${esc(item.pid ?? "—")}</td><td>${esc(item.process_name)}</td><td class="text-break">${esc(item.executable)}</td><td>${esc(fmtTime(item.process_start_time))}</td><td>${esc(fmtTime(item.first_detected_at))}</td><td>${esc(fmtTime(item.last_detected_at))}</td><td>${esc(item.state)}<small class="table-subtext">${esc(item.firewall_restriction)} · ${item.persistence_seconds ?? 0}s persistence${item.risk_indicators?.length ? ` · ${esc(item.risk_indicators.join(" "))}` : ""}</small></td><td>${esc(item.windows_service)}</td></tr>`).join("")
        : '<tr><td colspan="11" class="empty-state">No listening TCP ports or relevant UDP sockets detected.</td></tr>';
    }
    const events = $("portActivityList");
    if (events) {
      const items = value?.events || [];
      events.innerHTML = items.length ? items.map((item) => `<div class="event-row"><span class="event-marker ${["HIGH", "CRITICAL"].includes(item.details?.severity) || item.event_type.includes("FAILED") ? "error" : ""}"></span><div><strong>${esc(item.event_type)} · ${esc(item.details?.protocol || "")}/${esc(item.details?.port ?? "")} · ${esc(item.details?.process_name || "Process unavailable")} (PID ${esc(item.details?.pid ?? "unavailable")})</strong><small>${esc(fmtTime(item.details?.detected_at || item.created_at))} · ${esc(item.details?.local_address || "")} · ${esc(item.details?.executable || "Executable unavailable")}</small><p>${esc(item.details?.reason || "No reason recorded.")}</p><p><strong>Recommended:</strong> ${esc(item.details?.recommendation || "Review this event in context.")}</p></div></div>`).join("") : '<div class="empty-state">No port events recorded.</div>';
    }
  }

  function renderUrlScans(scans) {
    const body = $("urlHistoryTable");
    if (body) {
      body.innerHTML = scans?.length
        ? scans.map((item) => `<tr><td>${esc(fmtTime(item.created_at))}</td><td class="text-break">${esc(item.submitted_url)}</td><td class="text-break">${esc(item.normalized_url)}</td><td>${esc(item.analysis?.destination_type || "UNKNOWN")}</td><td><span class="severity ${severityClass(item.risk_level)}">${esc(item.risk_level)}</span></td><td>${esc(item.risk_score)}</td><td>${esc((item.analysis?.findings || []).map((finding) => finding.code).join(", ") || "None")}</td><td>${esc(item.analysis?.threat_intelligence?.status || "UNVERIFIED")}</td></tr>`).join("")
        : '<tr><td colspan="8" class="empty-state">No URL scans recorded.</td></tr>';
    }
    const recent = $("recentUrlFindings");
    if (recent) {
      recent.innerHTML = scans?.length
        ? scans.slice(0, 5).map((item) => `<div class="event-row"><span class="event-marker"></span><div><strong>${esc(item.risk_level)} heuristic indicators · ${esc(item.domain)} · ${esc(item.risk_score)}/100</strong><small>${esc(item.analysis?.destination_type || "UNKNOWN")} · ${esc(fmtTime(item.created_at))} · Reputation ${esc(item.analysis?.threat_intelligence?.status || "UNVERIFIED")}</small></div></div>`).join("")
        : '<div class="empty-state">No URL scans recorded.</div>';
    }
  }

  function renderUrlResult(result) {
    const panel = $("urlResultPanel");
    if (!panel) return;
    panel.hidden = false;
    $("urlScanTimestamp").textContent = `Scan #${result.id} · ${fmtTime(result.created_at)} · ${result.model}`;
    $("urlRiskLevel").textContent = result.risk_level;
    $("urlRiskLevel").className = `severity ${severityClass(result.risk_level)}`;
    $("urlRiskScore").textContent = `${result.risk_score}/100`;
    $("urlHttpsStatus").textContent = result.https ? "Yes (not sufficient)" : "No";
    $("urlReputationStatus").textContent = result.threat_intelligence.status;
    $("urlRedirectStatus").textContent = result.redirect_chain.status;
    $("urlSubmitted").textContent = result.submitted_url;
    $("urlNormalized").textContent = result.normalized_url;
    $("urlDomain").textContent = result.domain;
    $("urlDestinationType").textContent = result.destination_type || "UNKNOWN";
    $("urlDestinationMessage").textContent = result.destination_message || "Destination context is unknown.";
    const components = result.risk_components || {};
    $("urlRiskComponents").textContent = `Structural ${components.structural ?? "unknown"} · Destination ${components.destination ?? "unknown"} · Transport ${components.transport ?? "unknown"} · Reputation ${components.threat_reputation?.status || "UNVERIFIED"}`;
    $("urlRecommendation").textContent = result.recommended_action;
    $("urlFindings").innerHTML = result.findings.map((item) => `<tr><td><span class="severity ${severityClass(item.severity)}">${esc(item.severity)}</span></td><td>${esc(item.code)}</td><td>${esc(item.message)}</td><td>${esc(item.points)}</td></tr>`).join("");
    analyzedUrlToOpen = result.normalized_url;
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
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
    isAdministrator = data.administrator === true;
    const scan = data.latest_scan;
    const stale = data.assessment_status !== "verified" || scan?.status !== "verified";
    if (scan) renderOverview(scan, data.firewall_rules || [], stale, data.firewall_profiles, data.port_monitoring);
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
    renderFirewallProfiles(data.firewall_profiles, scan?.risk?.firewall_health);
    renderPortMonitoring(data.port_monitoring || {});
    renderUrlScans(data.url_scans || []);
    renderRiskUrlContext(scan?.risk?.url_security_observations);
    renderSecurityNotifications(data.security_notifications || []);
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
  const urlForm = $("urlScanForm");
  if (urlForm) urlForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const url = $("urlInput").value.trim();
    const button = urlForm.querySelector('button[type="submit"]');
    button.disabled = true;
    setStatus("Analyzing URL locally. No network request or third-party reputation lookup will be made.");
    try {
      const result = await getJson("/api/url-scans", {
        method: "POST",
        body: JSON.stringify({ url })
      });
      renderUrlResult(result);
      const sync = await refresh();
      setStatus(
        `URL assessment #${result.id}: ${result.risk_level} risk (${result.risk_score}/100). Reputation and redirects remain unverified.`,
        sync.ok ? "success" : "warning"
      );
    } catch (error) {
      setStatus(error.message, "error");
    } finally {
      button.disabled = false;
    }
  });
  const openAnalyzedUrl = $("openAnalyzedUrl");
  if (openAnalyzedUrl) openAnalyzedUrl.addEventListener("click", () => {
    if (!analyzedUrlToOpen) return;
    if (!window.confirm("This URL has not been reputation-checked, and the risk assessment cannot guarantee safety. Open it anyway?")) return;
    window.open(analyzedUrlToOpen, "_blank", "noopener,noreferrer");
  });
  const notificationFilter = $("notificationFilter");
  if (notificationFilter) notificationFilter.addEventListener("change", () => renderSecurityNotifications(securityNotifications));
  const menuToggle = $("menuToggle");
  if (menuToggle) menuToggle.addEventListener("click", () => $("sidebar").classList.toggle("open"));
  bindReportDownloads();
  enableTableSearch();
  refresh();
  setInterval(refresh, 5000);
})();

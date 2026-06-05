const state = {
  result: null,
  selectedIncident: null,
  neo4j: null,
  neo4jGraphs: {},
  sources: [],
  integrations: {},
  chatHistory: [],
};

const qs = (sel) => document.querySelector(sel);
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (m) => ({
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#039;",
}[m]));

function severityClass(value) {
  return ["low", "medium", "high", "critical"].includes(String(value).toLowerCase())
    ? String(value).toLowerCase()
    : "low";
}

function setStatus(text, mode = "neutral") {
  const el = qs("#runStatus");
  el.textContent = text;
  el.style.color = mode === "error" ? "#dc2626" : mode === "ok" ? "#059669" : "#64748b";
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch (err) {
    if (res.ok) {
      throw new Error(`Invalid JSON response from ${path}`);
    }
  }
  if (!res.ok) {
    throw new Error(`${res.status} ${text.slice(0, 180)}`);
  }
  if (data?.error) {
    throw new Error(`${data.error}: ${data.message || "request failed"}`);
  }
  return data;
}

async function loadSources() {
  const data = await api("/data-sources");
  state.sources = data.sources || [];
  state.integrations = data.integrations || {};
  const select = qs("#sourceSelect");
  select.innerHTML = state.sources.map((src) => `
    <option value="${esc(src.id)}">${esc(src.label)}</option>
  `).join("");
  select.value = data.recommended || "demo_reliable_attack";
  updateSourceHint();
  renderIntegrationStatus();
  renderMetrics(state.result?.summary || null);
  qs("#sourceCards").innerHTML = data.sources.map((src) => `
    <article class="source-card">
      <span class="pill">${esc(src.quality)}</span>
      <h3>${esc(src.label)}</h3>
      <p>${esc(src.notes)}</p>
      <p class="item-desc">Type: ${esc(src.kind || "source")} · ${src.runnable ? "Runnable from dropdown" : "Info only"}</p>
    </article>
  `).join("");
}

function renderIntegrationStatus() {
  const items = [
    ["VirusTotal", state.integrations.virustotal, "Public IP reputation enrichment"],
    ["AbuseIPDB", state.integrations.abuseipdb, "Abuse confidence scoring for public IPs"],
    ["macOS Logs", state.integrations.macos_logs, "Local unified logs through log show/log stream"],
    ["Windows Event Logs", state.integrations.windows_event_logs, "Security logs through PowerShell Get-WinEvent"],
  ];
  qs("#integrationStatus").innerHTML = items.map(([name, enabled, detail]) => `
    <article class="integration-card">
      <span>${enabled ? "Configured" : "Available"}</span>
      <strong>${esc(name)}</strong>
      <p>${esc(detail)}${enabled ? "" : " Add credentials or run on the matching host when required."}</p>
    </article>
  `).join("");
}

function updateSourceHint() {
  const selected = state.sources.find((src) => src.id === qs("#sourceSelect").value);
  if (!selected) {
    qs("#sourceHint").textContent = "Choose a source to run.";
    return;
  }
  const details = selected.kind === "synthetic"
    ? "Window, noise, and seed controls apply."
    : selected.id === "sample_csv"
      ? "Uses bundled Linux auth + network samples; numeric controls are ignored."
      : selected.id === "sample_windows_logs"
        ? "Uses bundled Windows authentication + network samples; numeric controls are ignored."
        : selected.id === "local_system_logs"
          ? "Uses local macOS unified logs; window minutes controls lookback."
          : selected.id === "windows_event_logs"
            ? "Requires running this API on Windows so PowerShell can read Security logs."
            : selected.id === "flog_access_logs"
              ? "Uses flog web logs blended with attack context for end-to-end demo signal."
              : "";
  qs("#sourceHint").textContent = `${selected.quality}: ${selected.notes} ${details}`;
}

function switchTab(tabId) {
  document.querySelectorAll(".tab-panel").forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.tab === tabId);
  });
  document.querySelectorAll(".nav a[data-tab]").forEach((link) => {
    link.classList.toggle("active", link.dataset.tab === tabId);
  });
  if (window.location.hash !== `#${tabId}`) {
    history.replaceState(null, "", `#${tabId}`);
  }
}

async function loadNeo4jStatus() {
  try {
    state.neo4j = await api("/neo4j/status");
    qs("#neo4jStatus").textContent = state.neo4j.connected
      ? `Neo4j connected: ${state.neo4j.user}@${state.neo4j.uri}`
      : `${state.neo4j.message} Local graph rendering is still available.`;
    qs("#mNeo4j").textContent = state.neo4j.connected ? "Connected" : "Local";
    qs("#openNeo4j").href = state.neo4j.browser_url || "http://localhost:7474";
  } catch (err) {
    qs("#neo4jStatus").textContent = `Neo4j status unavailable: ${err.message}`;
    qs("#mNeo4j").textContent = "Unknown";
  }
}

function renderMetrics(summary) {
  qs("#mSource").textContent = summary?.source?.split(":").pop() || "None";
  qs("#mEvents").textContent = summary?.events ?? 0;
  qs("#mDetections").textContent = summary?.detections ?? 0;
  qs("#mIncidents").textContent = summary?.incidents ?? 0;
  qs("#mSeverity").textContent = maxSeverity(state.result?.incidents || []);
  qs("#mStatus").textContent = summary?.detector_status?.reason ?? "Idle";
  qs("#mIntel").textContent =
    state.integrations.virustotal || state.integrations.abuseipdb ? "Enabled" : "Not Set";
}

function maxSeverity(incidents) {
  const order = { critical: 4, high: 3, medium: 2, low: 1 };
  const found = (incidents || [])
    .map((inc) => String(inc.severity || "low").toLowerCase())
    .sort((a, b) => (order[b] || 0) - (order[a] || 0))[0];
  return found ? found.toUpperCase() : "None";
}

function setEvidenceButtons(disabled) {
  qs("#runEvidence").disabled = disabled;
  qs("#runEvidencePanel").disabled = disabled;
}

function setChatAvailable(available) {
  qs("#chatInput").disabled = !available;
  qs("#sendChat").disabled = !available;
  qs("#chatIncidentSelect").disabled = !(state.result?.incidents || []).length;
  qs("#chatContext").textContent = available
    ? `Chatting with incident: ${state.selectedIncident.incident_id} - ${state.selectedIncident.title}`
    : "Run analysis and select an incident to chat with its evidence context.";
}

function resetChat() {
  state.chatHistory = [];
  renderChatMessages();
}

function renderChatMessages() {
  const root = qs("#chatMessages");
  const seed = state.chatHistory.length ? "" : `
    <div class="chat-message assistant">Ask about severity, affected user, timeline, evidence, MITRE mapping, recommended actions, or why the final decision should defer/escalate/close.</div>
  `;
  root.innerHTML = seed + state.chatHistory.map((msg) => `
    <div class="chat-message ${msg.role === "user" ? "user" : "assistant"}">${esc(msg.content)}</div>
  `).join("");
  root.scrollTop = root.scrollHeight;
}

function renderChatIncidentSelect() {
  const select = qs("#chatIncidentSelect");
  const incidents = state.result?.incidents || [];
  if (!incidents.length) {
    select.innerHTML = `<option value="">Run analysis to load incidents</option>`;
    select.disabled = true;
    return;
  }
  select.disabled = false;
  select.innerHTML = incidents.map((inc, idx) => `
    <option value="${idx}">${esc(inc.incident_id)} - ${esc(inc.title)}</option>
  `).join("");
  const selectedIdx = incidents.findIndex((inc) => inc.incident_id === state.selectedIncident?.incident_id);
  select.value = String(Math.max(selectedIdx, 0));
}

function selectIncident(inc) {
  if (!inc) {
    state.selectedIncident = null;
    resetChat();
    renderIncidentDetail(null);
    return;
  }
  if (state.selectedIncident?.incident_id !== inc.incident_id) {
    resetChat();
  }
  state.selectedIncident = inc;
  renderIncidents(state.result?.incidents || []);
  renderIncidentDetail(inc);
}

function renderDetections(detections) {
  const root = qs("#detectionsList");
  if (!detections?.length) {
    const status = state.result?.summary?.detector_status || {};
    const eventSummary = state.result?.summary?.event_summary || {};
    root.className = "list empty";
    root.innerHTML = `
      <div>No detections returned by the agentic detector.</div>
      <div class="item-desc">Reason: ${esc(status.reason || "unknown")} ${status.detail ? `- ${esc(status.detail)}` : ""}</div>
      <div class="item-desc">Event mix: ${esc(JSON.stringify(eventSummary.event_types || {}))}</div>
    `;
    return;
  }
  root.className = "list";
  root.innerHTML = detections.map((d) => `
    <article class="item">
      <div class="item-top">
        <div>
          <div class="item-title">${esc(d.name)}</div>
          <div class="item-desc">${esc(d.description)}</div>
        </div>
        <span class="severity ${severityClass(d.severity)}">${esc(d.severity)}</span>
      </div>
      <div class="item-desc">Confidence ${(Number(d.confidence || 0) * 100).toFixed(0)}% · Events ${d.event_count || 0} · Host ${esc(d.host || "unknown")}</div>
    </article>
  `).join("");
}

function renderIncidents(incidents) {
  const root = qs("#incidentsList");
  if (!incidents?.length) {
    root.className = "list empty";
    root.textContent = "No incidents correlated for this run.";
    renderChatIncidentSelect();
    renderIncidentDetail(null);
    return;
  }
  root.className = "list";
  root.innerHTML = incidents.map((inc, idx) => `
    <article class="item ${state.selectedIncident?.incident_id === inc.incident_id ? "active" : ""}" data-idx="${idx}">
      <div class="item-top">
        <div>
          <div class="item-title">${esc(inc.title)}</div>
          <div class="item-desc">${esc(inc.summary || "No summary available.")}</div>
        </div>
        <span class="severity ${severityClass(inc.severity)}">${esc(inc.severity)}</span>
      </div>
      <div class="item-desc">${esc(inc.incident_id)} · Timeline ${inc.timeline_count || 0} · KG ${inc.knowledge_graph_counts?.nodes || 0}/${inc.knowledge_graph_counts?.edges || 0}</div>
    </article>
  `).join("");
  root.querySelectorAll(".item").forEach((el) => {
    el.addEventListener("click", () => {
      selectIncident(incidents[Number(el.dataset.idx)]);
    });
  });
  if (!state.selectedIncident) {
    state.selectedIncident = incidents[0];
    renderIncidents(incidents);
    renderIncidentDetail(state.selectedIncident);
    return;
  }
  renderChatIncidentSelect();
}

function intelSummary(intel) {
  const ips = intel?.ips || {};
  const entries = Object.entries(ips);
  if (!entries.length) return "No public IP enrichment returned for this incident.";
  return entries.map(([ip, entry]) => {
    const vt = entry.virustotal || {};
    const ab = entry.abuseipdb || {};
    const stats = vt.last_analysis_stats || {};
    return `${ip}: VT malicious ${stats.malicious ?? "n/a"}, Abuse score ${ab.abuse_confidence_score ?? "n/a"}`;
  }).join("\n");
}

function renderIncidentDetail(inc) {
  const title = qs("#detailTitle");
  const root = qs("#incidentDetail");
  const syncButton = qs("#syncNeo4j");
  qs("#evidenceOutput").textContent = "Run evidence triage for a selected incident.";
  if (!inc) {
    title.textContent = "Select an incident";
    root.className = "detail-empty";
    root.textContent = "Incident timeline, enrichment, and knowledge graph summary will appear here.";
    setEvidenceButtons(true);
    setChatAvailable(false);
    renderChatIncidentSelect();
    syncButton.disabled = true;
    qs("#fetchNeo4j").disabled = true;
    renderGraph(null);
    qs("#graphSource").textContent = "No graph selected.";
    return;
  }
  title.textContent = inc.title;
  setEvidenceButtons(false);
  setChatAvailable(true);
  renderChatIncidentSelect();
  syncButton.disabled = false;
  qs("#fetchNeo4j").disabled = false;
  root.className = "detail-grid";
  root.innerHTML = `
    <div>
      <div class="kv"><span>Incident ID</span><strong>${esc(inc.incident_id)}</strong></div>
      <div class="kv"><span>User</span><strong>${esc(inc.affected_user || "unknown")}</strong></div>
      <div class="kv"><span>Host</span><strong>${esc(inc.affected_host || "unknown")}</strong></div>
      <div class="kv"><span>Source IP</span><strong>${esc(inc.primary_src_ip || "unknown")}</strong></div>
      <div class="kv"><span>Destination IP</span><strong>${esc(inc.primary_dst_ip || "unknown")}</strong></div>
      <div class="kv"><span>Knowledge Graph</span><strong>${inc.knowledge_graph_counts?.nodes || 0} nodes / ${inc.knowledge_graph_counts?.edges || 0} edges</strong></div>
      <h3>Threat intelligence</h3>
      <pre class="json-box">${esc(intelSummary(inc.enrichment_intel))}</pre>
    </div>
    <div>
      <h3>Timeline</h3>
      <ul class="timeline">
        ${(inc.timeline || []).slice(0, 8).map((t) => `
          <li><small>${esc(t.timestamp || "")} · ${esc(t.event_type || "")}</small>${esc(t.description || "")}</li>
        `).join("")}
      </ul>
    </div>
  `;
  const neo4jGraph = state.neo4jGraphs[inc.incident_id];
  renderGraph(neo4jGraph || inc.knowledge_graph || null);
  qs("#graphSource").textContent = neo4jGraph
    ? "Rendering graph fetched from Neo4j."
    : "Rendering local incident graph. Sync to Neo4j to store and read it from the graph database.";
  renderCypher(inc);
}

function colorForType(type) {
  const palette = {
    incident: "#2563eb",
    detection: "#7c3aed",
    user: "#059669",
    host: "#0891b2",
    ip: "#d97706",
    event_type: "#dc2626",
  };
  return palette[type] || "#64748b";
}

function shortLabel(value, max = 18) {
  const text = String(value || "");
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function renderGraph(kg) {
  const svg = qs("#graphSvg");
  if (!kg || !(kg.nodes || []).length) {
    svg.innerHTML = `<text x="380" y="230" text-anchor="middle" fill="#64748b" font-weight="800">Select an incident with a knowledge graph</text>`;
    return;
  }

  const nodes = kg.nodes || [];
  const edges = kg.edges || [];
  const w = 760;
  const h = 460;
  const cx = w / 2;
  const cy = h / 2;
  const radius = Math.min(180, 82 + nodes.length * 10);
  const positions = new Map();
  nodes.forEach((node, i) => {
    const angle = nodes.length === 1 ? 0 : (2 * Math.PI * i) / nodes.length - Math.PI / 2;
    const isIncident = node.type === "incident";
    positions.set(node.id, {
      x: isIncident ? cx : cx + Math.cos(angle) * radius,
      y: isIncident ? cy : cy + Math.sin(angle) * radius,
    });
  });

  const edgeSvg = edges.map((edge) => {
    const a = positions.get(edge.source);
    const b = positions.get(edge.target);
    if (!a || !b) return "";
    const mx = (a.x + b.x) / 2;
    const my = (a.y + b.y) / 2;
    return `
      <line class="graph-edge" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"></line>
      <text class="graph-label" x="${mx}" y="${my - 5}">${esc(edge.relation || "related")}</text>
    `;
  }).join("");

  const nodeSvg = nodes.map((node) => {
    const p = positions.get(node.id);
    const r = node.type === "incident" ? 34 : 28;
    return `
      <g class="graph-node">
        <circle cx="${p.x}" cy="${p.y}" r="${r}" fill="${colorForType(node.type)}"></circle>
        <text x="${p.x}" y="${p.y + r + 18}">${esc(shortLabel(node.label || node.id))}</text>
        <text x="${p.x}" y="${p.y + 4}" fill="#fff" style="fill:#fff;font-size:10px">${esc(shortLabel(node.type, 10))}</text>
      </g>
    `;
  }).join("");

  svg.innerHTML = `
    <defs>
      <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 0 L 10 5 L 0 10 z" fill="#94a3b8"></path>
      </marker>
    </defs>
    ${edgeSvg}
    ${nodeSvg}
  `;
}

function renderCypher(inc) {
  if (!inc) {
    qs("#cypherBox").textContent = "Select an incident to view the Neo4j query.";
    return;
  }
  const iid = String(inc.incident_id).replaceAll("\\", "\\\\").replaceAll("'", "\\'");
  qs("#cypherBox").textContent =
    `MATCH (n:KnowledgeNode {incident_id: '${iid}'})-[r:RELATED]->(m)\n` +
    `WHERE m.incident_id = '${iid}'\n` +
    "RETURN n, r, m\nLIMIT 500";
}

async function runAnalysis() {
  const body = {
    source_id: qs("#sourceSelect").value,
    window_minutes: Number(qs("#windowMinutes").value || 60),
    noise_events: Number(qs("#noiseEvents").value || 8),
    seed: Number(qs("#seed").value || 0) || null,
    include_reports: false,
  };
  state.result = null;
  state.selectedIncident = null;
  state.neo4jGraphs = {};
  resetChat();
  renderMetrics(null);
  setStatus("Running agentic analysis...");
  qs("#runAnalysis").disabled = true;
  try {
    const data = await api("/analyze-source", {
      method: "POST",
      body: JSON.stringify(body),
    });
    if (data.error) {
      throw new Error(`${data.error}: ${data.message || "source failed"}`);
    }
    state.result = data;
    renderMetrics(data.summary);
    renderDetections(data.detections);
    renderIncidents(data.incidents);
    setStatus(`Analysis complete: ${data.summary.detections} detections, ${data.summary.incidents} incidents.`, "ok");
    switchTab(data.summary.incidents ? "incidents" : "detections");
  } catch (err) {
    setStatus(`Analysis failed: ${err.message}`, "error");
  } finally {
    qs("#runAnalysis").disabled = false;
  }
}

async function runEvidenceTriage() {
  if (!state.selectedIncident) return;
  const out = qs("#evidenceOutput");
  out.textContent = "Running evidence triage...";
  qs("#runEvidence").disabled = true;
  qs("#runEvidencePanel").disabled = true;
  try {
    const data = await api(`/evidence-triage/${state.selectedIncident.incident_id}`, { method: "POST" });
    out.textContent = JSON.stringify({
      final_decision: data.final_decision,
      verifier: data.verifier,
      triage: data.triage,
    }, null, 2);
  } catch (err) {
    out.textContent = `Evidence triage failed: ${err.message}`;
  } finally {
    setEvidenceButtons(!state.selectedIncident);
  }
}

async function sendChat() {
  if (!state.selectedIncident) return;
  const input = qs("#chatInput");
  const prompt = input.value.trim();
  if (!prompt) return;
  input.value = "";
  state.chatHistory.push({ role: "user", content: prompt });
  renderChatMessages();
  qs("#sendChat").disabled = true;
  try {
    const data = await api("/chat", {
      method: "POST",
      body: JSON.stringify({
        incident_context: state.selectedIncident.context,
        history: state.chatHistory.slice(0, -1),
        prompt,
      }),
    });
    state.chatHistory.push({ role: "assistant", content: data.response || "No response returned." });
  } catch (err) {
    state.chatHistory.push({ role: "assistant", content: `Chat failed: ${err.message}` });
  } finally {
    renderChatMessages();
    qs("#sendChat").disabled = !state.selectedIncident;
  }
}

async function syncNeo4j() {
  if (!state.selectedIncident) return;
  const status = qs("#neo4jStatus");
  status.textContent = "Syncing selected incident to Neo4j...";
  qs("#syncNeo4j").disabled = true;
  try {
    const data = await api(`/neo4j/sync/${state.selectedIncident.incident_id}`, { method: "POST" });
    status.textContent = data.ok
      ? `${data.message} ${data.fetch_message || ""}`
      : `Neo4j sync failed: ${data.message}`;
    if (data.graph?.nodes?.length) {
      state.neo4jGraphs[state.selectedIncident.incident_id] = data.graph;
      renderGraph(data.graph);
      qs("#graphSource").textContent = "Rendering graph fetched from Neo4j after sync.";
    }
    if (data.cypher) qs("#cypherBox").textContent = data.cypher;
  } catch (err) {
    status.textContent = `Neo4j sync failed: ${err.message}`;
  } finally {
    qs("#syncNeo4j").disabled = false;
  }
}

async function fetchNeo4jGraph() {
  if (!state.selectedIncident) return;
  const status = qs("#neo4jStatus");
  status.textContent = "Fetching selected incident graph from Neo4j...";
  qs("#fetchNeo4j").disabled = true;
  try {
    const data = await api(`/neo4j/graph/${state.selectedIncident.incident_id}`);
    status.textContent = data.ok ? data.message : `Neo4j fetch failed: ${data.message}`;
    if (data.graph?.nodes?.length) {
      state.neo4jGraphs[state.selectedIncident.incident_id] = data.graph;
      renderGraph(data.graph);
      qs("#graphSource").textContent = "Rendering graph fetched from Neo4j.";
    }
    if (data.cypher) qs("#cypherBox").textContent = data.cypher;
  } catch (err) {
    status.textContent = `Neo4j fetch failed: ${err.message}`;
  } finally {
    qs("#fetchNeo4j").disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  document.querySelectorAll(".nav a[data-tab]").forEach((link) => {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      switchTab(link.dataset.tab);
    });
  });
  qs("#runAnalysis").addEventListener("click", runAnalysis);
  qs("#runEvidence").addEventListener("click", runEvidenceTriage);
  qs("#runEvidencePanel").addEventListener("click", runEvidenceTriage);
  qs("#syncNeo4j").addEventListener("click", syncNeo4j);
  qs("#fetchNeo4j").addEventListener("click", fetchNeo4jGraph);
  qs("#sendChat").addEventListener("click", sendChat);
  qs("#chatIncidentSelect").addEventListener("change", () => {
    const incidents = state.result?.incidents || [];
    selectIncident(incidents[Number(qs("#chatIncidentSelect").value)]);
  });
  qs("#chatInput").addEventListener("keydown", (event) => {
    if (event.key === "Enter") sendChat();
  });
  await loadSources();
  qs("#sourceSelect").addEventListener("change", updateSourceHint);
  await loadNeo4jStatus();
  const initialTab = window.location.hash?.replace("#", "") || "overview";
  switchTab(document.querySelector(`.tab-panel[data-tab="${initialTab}"]`) ? initialTab : "overview");
});

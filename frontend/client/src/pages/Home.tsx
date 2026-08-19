import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowDownRight,
  ArrowUpRight,
  BookOpen,
  Check,
  ChevronRight,
  CircleAlert,
  ClipboardList,
  Clock3,
  Code2,
  Database,
  Download,
  FileCheck2,
  Filter,
  Fingerprint,
  Gauge,
  GitBranch,
  HeartPulse,
  ListChecks,
  Server,
  Info,
  Layers3,
  LockKeyhole,
  Menu,
  Network,
  Play,
  RefreshCw,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  TerminalSquare,
  Users,
  Waypoints,
  X,
  Zap,
} from "lucide-react";

type Tone = "lime" | "red" | "amber" | "muted";

type Evidence = {
  id: string;
  action: string;
  reason: string;
  workload: string;
  destination: string;
  time: string;
  tone: Tone;
  detail: string;
};

const demoEvidence: Evidence[] = [
  { id: "dec-7f2a", action: "BLOCK", reason: "restricted field at egress", workload: "billing-worker", destination: "partner-webhook", time: "34 sec ago", tone: "red", detail: "customer_email remained confidential after transformation" },
  { id: "dec-7ef1", action: "ALLOW", reason: "policy v2.4 matched", workload: "analytics-workload", destination: "warehouse-internal", time: "2 min ago", tone: "lime", detail: "aggregate payload released with trusted provenance" },
  { id: "dec-7ed2", action: "REDACT", reason: "finance rule applied", workload: "finance-worker", destination: "erp-gateway", time: "5 min ago", tone: "amber", detail: "1 field omitted, payload reclassified, release approved" },
  { id: "dec-7e88", action: "BLOCK", reason: "direct bypass detected", workload: "unknown-workload", destination: "external-webhook", time: "8 min ago", tone: "red", detail: "request never entered the enforced gateway path" },
];

const apiBase = import.meta.env.VITE_TRACELOCK_API_URL || "http://localhost:8000";

function StatusDot({ tone = "lime" }: { tone?: Tone }) {
  return <span className={`status-dot status-${tone}`} aria-hidden="true" />;
}

function Metric({ label, value, note, tone = "lime", icon: Icon }: { label: string; value: string; note: string; tone?: Tone; icon: typeof Activity }) {
  return (
    <div className="metric-card">
      <div className="metric-top"><span className="eyebrow">{label}</span><Icon size={17} strokeWidth={1.6} /></div>
      <div className="metric-value"><StatusDot tone={tone} />{value}</div>
      <div className="metric-note">{note}</div>
    </div>
  );
}

function FlowNode({ number, title, subtitle, icon: Icon, active = false }: { number: string; title: string; subtitle: string; icon: typeof Activity; active?: boolean }) {
  return (
    <div className={`flow-node ${active ? "flow-node-active" : ""}`}>
      <div className="flow-node-number">{number}</div>
      <div className="flow-node-icon"><Icon size={19} strokeWidth={1.6} /></div>
      <div><strong>{title}</strong><span>{subtitle}</span></div>
    </div>
  );
}

function EvidenceRow({ item, onSelect }: { item: Evidence; onSelect: (item: Evidence) => void }) {
  return (
    <button className="evidence-row" onClick={() => onSelect(item)}>
      <div className={`evidence-icon evidence-${item.tone}`}><StatusDot tone={item.tone} /></div>
      <div className="evidence-main"><div><strong>{item.action}</strong><span>{item.reason}</span></div><small>{item.workload} <i>→</i> {item.destination}</small></div>
      <div className="evidence-time">{item.time}<ChevronRight size={15} /></div>
    </button>
  );
}

function ServiceView({ title, endpoint, description, icon: Icon }: { title: string; endpoint: string; description: string; icon: typeof Activity }) {
  const [payload, setPayload] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [updatedAt, setUpdatedAt] = useState("");

  const load = () => {
    setLoading(true);
    setError(null);
    fetch(`${apiBase}${endpoint}`, { signal: AbortSignal.timeout(4000) })
      .then(async (response) => {
        const body = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(`Gateway returned HTTP ${response.status}`);
        setPayload(body);
        setUpdatedAt(new Date().toLocaleTimeString());
      })
      .catch((reason) => setError(reason instanceof Error ? reason.message : "Unable to reach the gateway"))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, [endpoint]);

  const healthy = !error && !loading;
  return (
    <section className="service-view">
      <div className="service-hero">
        <div>
          <div className="eyebrow lime-text"><span className="signal-line" /> Gateway service</div>
          <h1>{title}</h1>
          <p>{description}</p>
        </div>
        <button className="button button-primary" onClick={load}><RefreshCw size={16} /> Refresh service</button>
      </div>
      <div className="service-toolbar"><span className={`service-status ${healthy ? "service-ok" : error ? "service-error" : "service-loading"}`}><StatusDot tone={healthy ? "lime" : error ? "red" : "amber"} /> {loading ? "Checking service" : error ? "Service unavailable" : "Service responding"}</span><code>{endpoint}</code>{updatedAt && <span>updated {updatedAt}</span>}</div>
      <div className="service-grid">
        <div className="panel service-response"><div className="panel-heading compact"><div><span className="eyebrow">Response</span><h2>{error ? "Could not read gateway" : "Live gateway payload"}</h2></div><Icon size={21} className="service-icon" /></div>{error ? <div className="service-error-copy"><CircleAlert size={20} /><p>{error}<br /><span>Make sure the backend is running on port 8000.</span></p></div> : <pre>{loading ? "Loading…" : JSON.stringify(payload, null, 2)}</pre>}</div>
        <div className="panel service-guide"><span className="eyebrow lime-text">What this view means</span><h2>Operate from the boundary.</h2><p>{endpoint === "/health" ? "Health confirms that the gateway process is alive." : endpoint === "/ready" ? "Readiness confirms that the gateway can serve traffic under its current configuration." : endpoint === "/v1/status" ? "Status summarizes the running TraceLock control plane and enforcement posture." : endpoint === "/v1/governance" ? "Governance shows whether evidence, policy, and production controls meet their operating requirements." : "Evidence is the durable decision trail. Raw payload values are intentionally excluded."}</p><div className="service-actions"><button className="button button-quiet" onClick={() => navigator.clipboard?.writeText(`${apiBase}${endpoint}`)}><Code2 size={15} /> Copy endpoint</button><a className="button button-quiet" href={`${apiBase}${endpoint}`} target="_blank" rel="noreferrer"><ArrowUpRight size={15} /> Open raw response</a></div></div>
      </div>
    </section>
  );
}

function JsonState({ value, loading, error }: { value: unknown; loading: boolean; error: string | null }) {
  if (loading) return <pre>Loading…</pre>;
  if (error) return <div className="service-error-copy"><CircleAlert size={20} /><p>{error}<br /><span>Confirm the gateway is running on port 8000.</span></p></div>;
  return <pre>{JSON.stringify(value, null, 2)}</pre>;
}

function DecisionLedgerView({ onSelect }: { onSelect: (item: Evidence) => void }) {
  const [records, setRecords] = useState<Record<string, unknown>[]>([]);
  const [action, setAction] = useState("");
  const [caseStatus, setCaseStatus] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const load = () => {
    setLoading(true); setError(null);
    const params = new URLSearchParams({ limit: "50" });
    if (action) params.set("action", action.toLowerCase());
    if (caseStatus) params.set("case_status", caseStatus);
    fetch(`${apiBase}/v1/evidence?${params.toString()}`, { signal: AbortSignal.timeout(5000) })
      .then(async (response) => { const body = await response.json(); if (!response.ok) throw new Error(`Gateway returned HTTP ${response.status}`); setRecords(Array.isArray(body.records) ? body.records : []); })
      .catch((reason) => setError(reason instanceof Error ? reason.message : "Unable to load evidence"))
      .finally(() => setLoading(false));
  };
  useEffect(() => { load(); }, [action, caseStatus]);
  const exportLedger = () => { const blob = new Blob([JSON.stringify(records, null, 2)], { type: "application/json" }); const url = URL.createObjectURL(blob); const anchor = document.createElement("a"); anchor.href = url; anchor.download = "tracelock-evidence.json"; anchor.click(); URL.revokeObjectURL(url); };
  return <section className="service-view"><div className="service-hero"><div><div className="eyebrow lime-text"><span className="signal-line" /> Operational evidence</div><h1>Decision ledger</h1><p>Search real gateway decisions, inspect the evidence record, and move cases through review without exposing raw payloads.</p></div><button className="button button-primary" onClick={exportLedger}><Download size={16} /> Export evidence</button></div><div className="ledger-controls"><div><Filter size={15} /><select value={action} onChange={(event) => setAction(event.target.value)}><option value="">All actions</option><option value="ALLOW">Allow</option><option value="BLOCK">Block</option><option value="REDACT">Redact</option></select></div><div><ClipboardList size={15} /><select value={caseStatus} onChange={(event) => setCaseStatus(event.target.value)}><option value="">All case states</option><option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="investigating">Investigating</option><option value="closed">Closed</option></select></div><button className="button button-quiet" onClick={load}><RefreshCw size={15} /> Refresh</button></div><div className="panel ledger-panel"><div className="panel-heading compact"><div><span className="eyebrow">Evidence store</span><h2>{loading ? "Loading decisions" : `${records.length} records returned`}</h2></div><span className="panel-meta"><StatusDot /> Raw payloads omitted</span></div>{error ? <div className="service-error-copy"><CircleAlert size={20} /><p>{error}</p></div> : records.length === 0 && !loading ? <div className="empty-state"><FileCheck2 size={24} /><strong>No evidence records match this filter.</strong><span>Decisions will appear here after the gateway processes traffic.</span></div> : <div className="ledger-table"><div className="ledger-head"><span>Action</span><span>Reason</span><span>Workload → destination</span><span>Case</span><span /></div>{records.map((record, index) => { const item: Evidence = { id: String(record.decision_id ?? `record-${index}`), action: String(record.action ?? "UNKNOWN").toUpperCase(), reason: String(record.reason_code ?? "policy decision"), workload: String(record.workload_id ?? "unknown"), destination: String(record.destination_id ?? "unknown"), time: String(record.created_at ?? record.timestamp ?? "recent"), tone: String(record.action).toLowerCase() === "block" ? "red" : String(record.action).toLowerCase() === "redact" ? "amber" : "lime", detail: "Evidence details are available in the review drawer." }; return <button className="ledger-row" key={item.id} onClick={() => onSelect(item)}><strong className={`ledger-action ledger-${item.tone}`}>{item.action}</strong><span>{item.reason}</span><code>{item.workload} → {item.destination}</code><span>{String(record.case_status ?? "open")}</span><ChevronRight size={15} /></button>; })}</div>}</div></section>;
}

function BoundaryView() {
  const [events, setEvents] = useState<unknown>(null); const [loading, setLoading] = useState(true); const [error, setError] = useState<string | null>(null);
  useEffect(() => { fetch(`${apiBase}/v1/boundary-events`, { signal: AbortSignal.timeout(4000) }).then(async (response) => { const body = await response.json(); if (!response.ok) throw new Error(`Gateway returned HTTP ${response.status}`); setEvents(body); }).catch((reason) => setError(reason instanceof Error ? reason.message : "Unable to load boundary events")).finally(() => setLoading(false)); }, []);
  return <section className="service-view"><div className="service-hero"><div><div className="eyebrow lime-text"><span className="signal-line" /> Network enforcement</div><h1>Boundary map</h1><p>TraceLock controls the route from workload to gateway to registered destination. Direct bypass is denied by topology, not only by application logic.</p></div><div className="api-pill online"><StatusDot /> Gateway-only egress</div></div><div className="boundary-map"><div className="boundary-node"><Code2 size={21} /><strong>Workload</strong><span>identity verified</span></div><div className="boundary-connector"><span>enforced path</span><i /></div><div className="boundary-node boundary-node-active"><LockKeyhole size={21} /><strong>TraceLock gateway</strong><span>policy + evidence</span></div><div className="boundary-connector"><span>registered egress</span><i /></div><div className="boundary-node"><Database size={21} /><strong>Destination</strong><span>receipt expected</span></div></div><div className="panel boundary-events"><div className="panel-heading compact"><div><span className="eyebrow">Boundary events</span><h2>Observed enforcement signals</h2></div><Network size={20} className="service-icon" /></div><JsonState value={events} loading={loading} error={error} /></div></section>;
}

function PolicyView() {
  const [policy, setPolicy] = useState<unknown>(null); const [loading, setLoading] = useState(true); const [error, setError] = useState<string | null>(null); const [classification, setClassification] = useState("confidential"); const [destination, setDestination] = useState("external-webhook"); const [result, setResult] = useState("");
  useEffect(() => { fetch(`${apiBase}/v1/policy`, { signal: AbortSignal.timeout(4000) }).then(async (response) => { const body = await response.json(); if (!response.ok) throw new Error(`Gateway returned HTTP ${response.status}`); setPolicy(body); }).catch((reason) => setError(reason instanceof Error ? reason.message : "Unable to load policy")).finally(() => setLoading(false)); }, []);
  const simulate = () => setResult(classification === "public" || destination.includes("internal") ? "DRY RUN: likely ALLOW path — verify with a real gateway request." : "DRY RUN: likely BLOCK or REDACT path — sensitive data is not assumed safe at external egress.");
  return <section className="service-view"><div className="service-hero"><div><div className="eyebrow lime-text"><span className="signal-line" /> Policy intelligence</div><h1>Policy simulator</h1><p>Explore policy context without sending a receiver request. This screen is a simulation only; the gateway remains the final authority.</p></div><div className="api-pill"><StatusDot tone={error ? "red" : "lime"} /> {error ? "Policy unavailable" : "Policy loaded"}</div></div><div className="simulator-grid"><div className="panel simulator-form"><span className="eyebrow">Dry-run inputs</span><h2>Would this flow be safe?</h2><label>Data classification<select value={classification} onChange={(event) => setClassification(event.target.value)}><option value="public">Public</option><option value="internal">Internal</option><option value="confidential">Confidential</option><option value="restricted">Restricted</option></select></label><label>Destination<select value={destination} onChange={(event) => setDestination(event.target.value)}><option value="warehouse-internal">warehouse-internal</option><option value="erp-gateway">erp-gateway</option><option value="external-webhook">external-webhook</option></select></label><button className="button button-primary" onClick={simulate}><Play size={15} /> Run dry simulation</button>{result && <div className="simulation-result"><StatusDot tone={result.includes("ALLOW") ? "lime" : "amber"} /><span>{result}</span></div>}</div><div className="panel"><div className="panel-heading compact"><div><span className="eyebrow">Active policy</span><h2>Loaded gateway policy</h2></div><FileCheck2 size={20} className="service-icon" /></div><JsonState value={policy} loading={loading} error={error} /></div></div></section>;
}

function AdminView() {
  const [destinations, setDestinations] = useState<unknown>(null); const [loading, setLoading] = useState(true); const [error, setError] = useState<string | null>(null);
  useEffect(() => { fetch(`${apiBase}/v1/destinations`, { signal: AbortSignal.timeout(4000) }).then(async (response) => { const body = await response.json(); if (!response.ok) throw new Error(`Gateway returned HTTP ${response.status}`); setDestinations(body); }).catch((reason) => setError(reason instanceof Error ? reason.message : "Unable to load destinations")).finally(() => setLoading(false)); }, []);
  return <section className="service-view"><div className="service-hero"><div><div className="eyebrow lime-text"><span className="signal-line" /> Operations</div><h1>Integrations</h1><p>Review registered destinations and the controlled egress points that TraceLock is allowed to reach.</p></div><div className="api-pill"><StatusDot /> Registered destinations</div></div><div className="admin-grid"><div className="panel admin-card"><div className="mini-icon lime-box"><Waypoints size={18} /></div><h2>Destinations</h2><p>Only registered destinations can receive authorized traffic through the gateway.</p><JsonState value={destinations} loading={loading} error={error} /></div><div className="panel admin-card"><div className="mini-icon blue-box"><Users size={18} /></div><h2>Workload identities</h2><p>Identity verification remains enforced before policy evaluation. Identity administration is ready for the next connected registry.</p><div className="empty-state"><Users size={22} /><span>No identity registry records exposed by the current API.</span></div></div></div></section>;
}

function SettingsView() {
  const [apiUrl, setApiUrl] = useState(apiBase); const [saved, setSaved] = useState(false); const save = () => { localStorage.setItem("tracelock-api-url", apiUrl); setSaved(true); };
  return <section className="service-view"><div className="service-hero"><div><div className="eyebrow lime-text"><span className="signal-line" /> Control Center configuration</div><h1>Settings</h1><p>Keep the dashboard pointed at the gateway you want to observe. This setting changes the frontend target only.</p></div><div className="api-pill"><StatusDot /> Local operator</div></div><div className="panel settings-card"><span className="eyebrow">Gateway connection</span><h2>API base URL</h2><div className="settings-row"><input value={apiUrl} onChange={(event) => { setApiUrl(event.target.value); setSaved(false); }} /><button className="button button-primary" onClick={save}>Save target</button></div>{saved && <div className="simulation-result"><StatusDot /><span>Saved locally. Reload the page to use the new target.</span></div>}<div className="settings-note"><Info size={16} /><span>Use the Docker Compose default `http://localhost:8000` unless you are connecting to another TraceLock environment.</span></div></div></section>;
}

export default function Home() {
  const [activeNav, setActiveNav] = useState("Overview");
  const [selected, setSelected] = useState<Evidence | null>(null);
  const [apiOnline, setApiOnline] = useState(false);
  const [mobileNav, setMobileNav] = useState(false);
  const [lastRefresh, setLastRefresh] = useState("just now");
  const [liveStatus, setLiveStatus] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    Promise.all([
      fetch(`${apiBase}/health`, { signal: AbortSignal.timeout(1600) }),
      fetch(`${apiBase}/v1/status`, { signal: AbortSignal.timeout(2200) }),
    ])
      .then(async ([healthResponse, statusResponse]) => {
        setApiOnline(healthResponse.ok);
        if (statusResponse.ok) setLiveStatus(await statusResponse.json());
      })
      .catch(() => setApiOnline(false));
  }, [lastRefresh]);

  const boundary = (liveStatus?.boundary ?? {}) as Record<string, unknown>;
  const capabilities = (liveStatus?.capabilities ?? {}) as Record<string, unknown>;
  const evidenceCount = typeof boundary.evidence_count === "number" ? boundary.evidence_count : "—";
  const eventCount = typeof boundary.event_count === "number" ? boundary.event_count : "—";
  const governanceValid = boundary.governance_valid === true;
  const evidenceReady = boundary.evidence_ready === true;
  const nav = [
    { label: "Overview", icon: Activity },
    { label: "Health", icon: HeartPulse },
    { label: "Readiness", icon: ListChecks },
    { label: "Gateway status", icon: Server },
    { label: "Governance", icon: ShieldCheck },
    { label: "Evidence API", icon: Database },
    { label: "Decision ledger", icon: FileCheck2 },
    { label: "Policy & provenance", icon: Fingerprint },
    { label: "Network boundary", icon: Network },
  ];

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileNav ? "sidebar-open" : ""}`}>
        <div className="brand-lockup"><img src="/tracelock-logo-mark.svg" alt="TraceLock mark" /><div><strong>TraceLock</strong><span>Control Center</span></div><button className="mobile-close" onClick={() => setMobileNav(false)}><X size={18} /></button></div>
        <button className="workspace-switcher" onClick={() => { setActiveNav("Settings"); setMobileNav(false); }}><span className="workspace-dot" />Local gateway <ChevronRight size={14} /></button>
        <div className="nav-label">Observe</div>
        <nav>{nav.map(({ label, icon: Icon }) => <button key={label} className={activeNav === label ? "nav-item active" : "nav-item"} onClick={() => { setActiveNav(label); setMobileNav(false); }}><Icon size={17} /><span>{label}</span>{label === "Decision ledger" && <em>4</em>}</button>)}</nav>
        <div className="nav-label nav-label-lower">System</div>
        <nav><button className="nav-item" onClick={() => setActiveNav("Integrations")}><GitBranch size={17} /><span>Integrations</span></button><button className="nav-item" onClick={() => setActiveNav("Settings")}><SlidersHorizontal size={17} /><span>Settings</span></button></nav>
        <div className="sidebar-bottom"><div className="sidebar-health"><StatusDot /><div><strong>Gateway healthy</strong><span>Evidence durable</span></div></div><div className="sidebar-version"><span>TraceLock v0.1.0</span><span>LOCAL / DEMO</span></div></div>
      </aside>

      <main className="main-canvas">
        <header className="topbar"><button className="mobile-menu" onClick={() => setMobileNav(true)}><Menu size={20} /></button><div className="breadcrumb"><span>Control Center</span><ChevronRight size={14} /><strong>{activeNav}</strong></div><div className="top-actions"><div className={`api-pill ${apiOnline ? "online" : "demo"}`}><StatusDot tone={apiOnline ? "lime" : "amber"} />{apiOnline ? "Live gateway" : "Demo snapshot"}</div><button className="icon-button" onClick={() => setLastRefresh(new Date().toLocaleTimeString())} title="Refresh gateway data"><RefreshCw size={17} /></button><button className="avatar" onClick={() => setActiveNav("Settings")} title="Open operator settings">VG</button></div></header>
        <div className="content-wrap">
          {activeNav === "Decision ledger" ? <DecisionLedgerView onSelect={setSelected} /> : activeNav === "Network boundary" ? <BoundaryView /> : activeNav === "Policy & provenance" ? <PolicyView /> : activeNav === "Integrations" ? <AdminView /> : activeNav === "Settings" ? <SettingsView /> : activeNav !== "Overview" ? <ServiceView title={activeNav} endpoint={activeNav === "Health" ? "/health" : activeNav === "Readiness" ? "/ready" : activeNav === "Gateway status" ? "/v1/status" : activeNav === "Governance" ? "/v1/governance" : "/v1/evidence"} description="A visual gateway view for checking TraceLock without leaving the Control Center." icon={activeNav === "Health" ? HeartPulse : activeNav === "Readiness" ? ListChecks : activeNav === "Gateway status" ? Server : activeNav === "Governance" ? ShieldCheck : Database} /> : null}
          {activeNav === "Overview" && <>
          <section className="intro-row"><div><div className="eyebrow lime-text"><span className="signal-line" /> System overview</div><h1>See what crossed<br /><i>the boundary.</i></h1><p className="intro-copy">TraceLock is the authorization and evidence layer for controlled data egress. It checks <strong>who is sending</strong>, <strong>what data is moving</strong>, and <strong>why the destination is allowed</strong>—before a request leaves.</p></div><div className="intro-actions"><button className="button button-primary" onClick={() => setActiveNav("Decision ledger")}><Search size={16} /> Inspect decisions</button><button className="button button-quiet" onClick={() => setActiveNav("Network boundary")}><BookOpen size={16} /> How it works</button></div></section>

          <section className="signal-panel"><div className="panel-heading"><div><span className="eyebrow">Live enforcement path</span><h2>Every release has a reason.</h2></div><div className="panel-meta"><StatusDot /> <span>Last signal {lastRefresh}</span></div></div><div className="flow-map"><div className="flow-line"><span className="line-track" /><span className="line-progress" /><span className="line-marker marker-one" /><span className="line-marker marker-two" /><span className="line-marker marker-three" /></div><FlowNode number="01" title="Workload" subtitle="identity verified" icon={Code2} /><FlowNode number="02" title="Gateway" subtitle="request buffered" icon={LockKeyhole} active /><FlowNode number="03" title="Policy" subtitle="v2.4 / matched" icon={FileCheck2} active /><FlowNode number="04" title="Destination" subtitle="registered / safe" icon={Database} active /></div><div className="signal-footer"><span><StatusDot /> Direct bypass <strong>denied</strong></span><span><StatusDot /> Evidence store <strong>durable</strong></span><span><StatusDot tone="amber" /> Review queue <strong>4 items</strong></span></div></section>

          <section className="metrics-grid"><Metric label="Boundary events" value={`${eventCount}`} note="reported by gateway" icon={Activity} /><Metric label="Evidence records" value={`${evidenceCount}`} note={evidenceReady ? "durable store ready" : "store status unavailable"} tone={evidenceReady ? "lime" : "amber"} icon={ShieldCheck} /><Metric label="Governance posture" value={liveStatus ? (governanceValid ? "VALID" : "CHECK") : "—"} note="derived from /v1/status" tone={governanceValid ? "lime" : "amber"} icon={CircleAlert} /><Metric label="Policy engine" value={liveStatus ? (capabilities.deterministic_policy ? "READY" : "CHECK") : "—"} note="deterministic evaluation" tone={capabilities.deterministic_policy ? "lime" : "amber"} icon={Gauge} /></section>

          <section className="lower-grid"><div className="panel evidence-panel"><div className="panel-heading compact"><div><span className="eyebrow">Decision ledger</span><h2>Recent enforcement signals</h2></div><button className="text-button" onClick={() => setActiveNav("Decision ledger")}>View ledger <ArrowUpRight size={14} /></button></div><div className="evidence-list">{demoEvidence.map((item) => <EvidenceRow key={item.id} item={item} onSelect={setSelected} />)}</div></div><div className="panel explain-panel"><div className="explain-art"><div className="evidence-art-grid"><img src="/tracelock-logo-mark.svg" alt="TraceLock evidence mark" /></div><div className="art-overlay" /></div><div className="explain-copy"><span className="eyebrow lime-text">Evidence, without leakage</span><h2>Prove the decision<br />without storing the payload.</h2><p>TraceLock records hashes, policy versions, classifications, and receiver receipts. It never needs to put the raw body into your audit trail.</p><button className="text-button" onClick={() => setActiveNav("Decision ledger")}>Explore evidence <ArrowUpRight size={14} /></button></div></div></section>

          <section className="bottom-grid"><button className="mini-card" onClick={() => setActiveNav("Policy & provenance")}><div className="mini-icon lime-box"><Fingerprint size={18} /></div><div><span className="eyebrow">Trusted provenance</span><strong>Classification is sticky</strong><p>Renaming or encoding a field cannot quietly lower its sensitivity.</p></div><ArrowUpRight size={16} /></button><button className="mini-card" onClick={() => setActiveNav("Policy & provenance")}><div className="mini-icon amber-box"><Zap size={18} /></div><div><span className="eyebrow">Transformation</span><strong>Redact, reclassify, re-evaluate</strong><p>Allowed transformations are checked again before release.</p></div><ArrowUpRight size={16} /></button><button className="mini-card" onClick={() => setActiveNav("Network boundary")}><div className="mini-icon blue-box"><TerminalSquare size={18} /></div><div><span className="eyebrow">Honest boundary</span><strong>What TraceLock cannot see</strong><p>Traffic outside the enforced gateway path is marked unmonitored.</p></div><ArrowUpRight size={16} /></button></section>
          <footer className="footer"><span>TraceLock Control Center · local demonstration</span><span><StatusDot /> All core controls operational</span></footer>
          </>}
        </div>
      </main>

      {selected && <div className="drawer-backdrop" onClick={() => setSelected(null)}><aside className="decision-drawer" onClick={(event) => event.stopPropagation()}><div className="drawer-top"><div><span className="eyebrow">Decision evidence</span><h2>{selected.action.toLowerCase()} at the boundary</h2></div><button className="icon-button" onClick={() => setSelected(null)}><X size={18} /></button></div><div className={`decision-banner banner-${selected.tone}`}><StatusDot tone={selected.tone} /><div><strong>{selected.action}</strong><span>{selected.reason}</span></div></div><div className="drawer-detail"><div><span>Decision ID</span><strong>{selected.id}</strong></div><div><span>Workload</span><strong>{selected.workload}</strong></div><div><span>Destination</span><strong>{selected.destination}</strong></div><div><span>Receiver requests</span><strong>{selected.action === "BLOCK" ? "0 · not observed" : "1 · receipt confirmed"}</strong></div><div className="detail-wide"><span>Evidence note</span><p>{selected.detail}</p></div></div><div className="drawer-footer"><FileCheck2 size={17} /><span>Payload values are intentionally omitted from this record.</span></div></aside></div>}
    </div>
  );
}

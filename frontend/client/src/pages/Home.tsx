import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowDownRight,
  ArrowUpRight,
  BookOpen,
  Check,
  ChevronRight,
  CircleAlert,
  Clock3,
  Code2,
  Database,
  FileCheck2,
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
  RefreshCw,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  TerminalSquare,
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

export default function Home() {
  const [activeNav, setActiveNav] = useState("Overview");
  const [selected, setSelected] = useState<Evidence | null>(null);
  const [apiOnline, setApiOnline] = useState(false);
  const [mobileNav, setMobileNav] = useState(false);
  const [lastRefresh, setLastRefresh] = useState("just now");

  useEffect(() => {
    fetch(`${apiBase}/health`, { signal: AbortSignal.timeout(1600) })
      .then((response) => setApiOnline(response.ok))
      .catch(() => setApiOnline(false));
  }, [lastRefresh]);

  const counts = useMemo(() => ({ blocked: 14, released: 286, redacted: 31 }), []);
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
        <div className="brand-lockup"><img src="/manus-storage/tracelock-mark_249631b5.png" alt="TraceLock mark" /><div><strong>TraceLock</strong><span>Control Center</span></div><button className="mobile-close" onClick={() => setMobileNav(false)}><X size={18} /></button></div>
        <div className="workspace-switcher"><span className="workspace-dot" />Local gateway <ChevronRight size={14} /></div>
        <div className="nav-label">Observe</div>
        <nav>{nav.map(({ label, icon: Icon }) => <button key={label} className={activeNav === label ? "nav-item active" : "nav-item"} onClick={() => { setActiveNav(label); setMobileNav(false); }}><Icon size={17} /><span>{label}</span>{label === "Decision ledger" && <em>4</em>}</button>)}</nav>
        <div className="nav-label nav-label-lower">System</div>
        <nav><button className="nav-item" onClick={() => setActiveNav("Integrations")}><GitBranch size={17} /><span>Integrations</span></button><button className="nav-item" onClick={() => setActiveNav("Settings")}><SlidersHorizontal size={17} /><span>Settings</span></button></nav>
        <div className="sidebar-bottom"><div className="sidebar-health"><StatusDot /><div><strong>Gateway healthy</strong><span>Evidence durable</span></div></div><div className="sidebar-version"><span>TraceLock v0.1.0</span><span>LOCAL / DEMO</span></div></div>
      </aside>

      <main className="main-canvas">
        <header className="topbar"><button className="mobile-menu" onClick={() => setMobileNav(true)}><Menu size={20} /></button><div className="breadcrumb"><span>Control Center</span><ChevronRight size={14} /><strong>{activeNav}</strong></div><div className="top-actions"><div className={`api-pill ${apiOnline ? "online" : "demo"}`}><StatusDot tone={apiOnline ? "lime" : "amber"} />{apiOnline ? "Live gateway" : "Demo snapshot"}</div><button className="icon-button" onClick={() => setLastRefresh(new Date().toLocaleTimeString())} title="Refresh"><RefreshCw size={17} /></button><div className="avatar">VG</div></div></header>
        <div className="content-wrap">
          {activeNav !== "Overview" && activeNav !== "Decision ledger" && activeNav !== "Policy & provenance" && activeNav !== "Network boundary" && activeNav !== "Integrations" && activeNav !== "Settings" ? <ServiceView title={activeNav} endpoint={activeNav === "Health" ? "/health" : activeNav === "Readiness" ? "/ready" : activeNav === "Gateway status" ? "/v1/status" : activeNav === "Governance" ? "/v1/governance" : "/v1/evidence"} description="A visual gateway view for checking TraceLock without leaving the Control Center." icon={activeNav === "Health" ? HeartPulse : activeNav === "Readiness" ? ListChecks : activeNav === "Gateway status" ? Server : activeNav === "Governance" ? ShieldCheck : Database} /> : null}
          {activeNav === "Overview" && <>
          <section className="intro-row"><div><div className="eyebrow lime-text"><span className="signal-line" /> System overview</div><h1>See what crossed<br /><i>the boundary.</i></h1><p className="intro-copy">TraceLock is the authorization and evidence layer for controlled data egress. It checks <strong>who is sending</strong>, <strong>what data is moving</strong>, and <strong>why the destination is allowed</strong>—before a request leaves.</p></div><div className="intro-actions"><button className="button button-primary" onClick={() => setActiveNav("Decision ledger")}><Search size={16} /> Inspect decisions</button><button className="button button-quiet" onClick={() => setActiveNav("Network boundary")}><BookOpen size={16} /> How it works</button></div></section>

          <section className="signal-panel"><div className="panel-heading"><div><span className="eyebrow">Live enforcement path</span><h2>Every release has a reason.</h2></div><div className="panel-meta"><StatusDot /> <span>Last signal {lastRefresh}</span></div></div><div className="flow-map"><div className="flow-line"><span className="line-track" /><span className="line-progress" /><span className="line-marker marker-one" /><span className="line-marker marker-two" /><span className="line-marker marker-three" /></div><FlowNode number="01" title="Workload" subtitle="identity verified" icon={Code2} /><FlowNode number="02" title="Gateway" subtitle="request buffered" icon={LockKeyhole} active /><FlowNode number="03" title="Policy" subtitle="v2.4 / matched" icon={FileCheck2} active /><FlowNode number="04" title="Destination" subtitle="registered / safe" icon={Database} active /></div><div className="signal-footer"><span><StatusDot /> Direct bypass <strong>denied</strong></span><span><StatusDot /> Evidence store <strong>durable</strong></span><span><StatusDot tone="amber" /> Review queue <strong>4 items</strong></span></div></section>

          <section className="metrics-grid"><Metric label="Requests observed" value="331" note="last 24 hours · +12.4%" icon={Activity} /><Metric label="Released safely" value={`${counts.released}`} note="86.4% of observed flow" icon={ShieldCheck} /><Metric label="Blocked at boundary" value={`${counts.blocked}`} note="zero receiver requests" tone="red" icon={CircleAlert} /><Metric label="Evidence latency" value="18ms" note="p95 · within target" icon={Gauge} /></section>

          <section className="lower-grid"><div className="panel evidence-panel"><div className="panel-heading compact"><div><span className="eyebrow">Decision ledger</span><h2>Recent enforcement signals</h2></div><button className="text-button" onClick={() => setActiveNav("Decision ledger")}>View ledger <ArrowUpRight size={14} /></button></div><div className="evidence-list">{demoEvidence.map((item) => <EvidenceRow key={item.id} item={item} onSelect={setSelected} />)}</div></div><div className="panel explain-panel"><div className="explain-art"><img src="/manus-storage/tracelock-evidence-tray_9ee0dc01.jpg" alt="Evidence tray illustration" /><div className="art-overlay" /></div><div className="explain-copy"><span className="eyebrow lime-text">Evidence, without leakage</span><h2>Prove the decision<br />without storing the payload.</h2><p>TraceLock records hashes, policy versions, classifications, and receiver receipts. It never needs to put the raw body into your audit trail.</p><button className="text-button" onClick={() => setActiveNav("Decision ledger")}>Explore evidence <ArrowUpRight size={14} /></button></div></div></section>

          <section className="bottom-grid"><div className="mini-card"><div className="mini-icon lime-box"><Fingerprint size={18} /></div><div><span className="eyebrow">Trusted provenance</span><strong>Classification is sticky</strong><p>Renaming or encoding a field cannot quietly lower its sensitivity.</p></div><ArrowUpRight size={16} /></div><div className="mini-card"><div className="mini-icon amber-box"><Zap size={18} /></div><div><span className="eyebrow">Transformation</span><strong>Redact, reclassify, re-evaluate</strong><p>Allowed transformations are checked again before release.</p></div><ArrowUpRight size={16} /></div><div className="mini-card"><div className="mini-icon blue-box"><TerminalSquare size={18} /></div><div><span className="eyebrow">Honest boundary</span><strong>What TraceLock cannot see</strong><p>Traffic outside the enforced gateway path is marked unmonitored.</p></div><ArrowUpRight size={16} /></div></section>
          <footer className="footer"><span>TraceLock Control Center · local demonstration</span><span><StatusDot /> All core controls operational</span></footer>
          </>}
        </div>
      </main>

      {selected && <div className="drawer-backdrop" onClick={() => setSelected(null)}><aside className="decision-drawer" onClick={(event) => event.stopPropagation()}><div className="drawer-top"><div><span className="eyebrow">Decision evidence</span><h2>{selected.action.toLowerCase()} at the boundary</h2></div><button className="icon-button" onClick={() => setSelected(null)}><X size={18} /></button></div><div className={`decision-banner banner-${selected.tone}`}><StatusDot tone={selected.tone} /><div><strong>{selected.action}</strong><span>{selected.reason}</span></div></div><div className="drawer-detail"><div><span>Decision ID</span><strong>{selected.id}</strong></div><div><span>Workload</span><strong>{selected.workload}</strong></div><div><span>Destination</span><strong>{selected.destination}</strong></div><div><span>Receiver requests</span><strong>{selected.action === "BLOCK" ? "0 · not observed" : "1 · receipt confirmed"}</strong></div><div className="detail-wide"><span>Evidence note</span><p>{selected.detail}</p></div></div><div className="drawer-footer"><FileCheck2 size={17} /><span>Payload values are intentionally omitted from this record.</span></div></aside></div>}
    </div>
  );
}

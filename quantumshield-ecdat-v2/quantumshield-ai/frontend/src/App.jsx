import React, { useState, useMemo, useEffect, useCallback, useRef } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import BackgroundVideo from "./BackgroundVideo";
import {
  RadialBarChart, RadialBar, ResponsiveContainer, AreaChart, Area,
  XAxis, YAxis, Tooltip, CartesianGrid, BarChart, Bar, Cell,
} from "recharts";
import {
  ShieldCheck, Atom, KeyRound, Lock, Bug, FileWarning, Send, ChevronDown,
  LayoutGrid, ListChecks, FileText, Sparkles, RefreshCw, UploadCloud,
  Loader2, AlertCircle, Settings2, Download, X, CheckCircle2, Boxes,
  Globe, Server, HelpCircle, Clock, Package, ServerCog,
  GitBranch, Network, TrendingUp, Shield, BarChart3, Ticket, GitMerge,
  ChevronRight, ZapOff, Zap, Copy, ExternalLink,
} from "lucide-react";

/* -------------------------------------------------------------------------
   Design tokens — flat charcoal, one functional accent, severity colors
   carry meaning. IBM Plex Sans/Mono pairing.
------------------------------------------------------------------------- */
const C = {
  bg: "#0C0E12",
  panel: "#14171D",
  panelRaised: "#181C23",
  border: "#2A303B",
  text: "#F2F4F7",
  textMuted: "#AAB2C0",
  textFaint: "#828A98",
  accent: "#4C8BF5",
  accentDim: "#2B3B57",
  critical: "#F0555C",
  high: "#F0A23C",
  medium: "#D8C13A",
  low: "#3FCB8F",
};
const SEVERITY_COLOR = { critical: C.critical, high: C.high, medium: C.medium, low: C.low };
const FONT = "'IBM Plex Sans', system-ui, sans-serif";
const MONO = "'IBM Plex Mono', monospace";
const DEFAULT_API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000/api/v1";

const CATEGORY_ICON = {
  secret: KeyRound,
  quantum_vulnerable_crypto: Atom,
  classical_crypto_weakness: Lock,
  auth_weakness: Bug,
  dependency_cve: FileWarning,
  certificate_issue: FileText,
  crypto_library: Package,
  hsm_cloud_kms: ServerCog,
  binary_artifact: Boxes,
};

const CRITICALITY_COLOR = { critical: "F0555C", high: "F0A23C", medium: "D8C13A", low: "3FCB8F" };
const MOSCA_COLOR = { at_risk: "F0555C", watch: "F0A23C", safe: "3FCB8F", not_applicable: "5B6270" };
const EXPOSURE_ICON = { external: Globe, internal: Server, unknown: HelpCircle };

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  componentDidCatch(error, errorInfo) {
    console.error("Dashboard render error:", error, errorInfo);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen w-full flex items-center justify-center p-6" style={{ background: C.bg, color: C.text, fontFamily: FONT }}>
          <div className="max-w-md p-6 rounded-lg text-center" style={{ background: C.panel, border: `1px solid ${C.critical}` }}>
            <AlertCircle size={36} color={C.critical} className="mx-auto mb-3" />
            <h2 className="text-lg font-bold mb-2">Rendering Display Error</h2>
            <p className="text-[12px] mb-4 text-left p-3 rounded" style={{ background: C.panelRaised, color: C.textMuted, fontFamily: MONO }}>
              {this.state.error?.message || "An unexpected error occurred while rendering the dashboard."}
            </p>
            <button
              onClick={() => { this.setState({ hasError: false }); window.location.reload(); }}
              className="px-4 py-2 rounded text-[13px] font-semibold"
              style={{ background: C.accent, color: "#0C0E12" }}
            >
              Reload Dashboard
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

const NAV_ITEMS = [
  { key: "overview", label: "Overview", icon: LayoutGrid },
  { key: "findings", label: "Findings", icon: ListChecks },
  { key: "inventory", label: "Asset Inventory", icon: Boxes },
  { key: "quantum", label: "Quantum Readiness", icon: Atom },
  { key: "reports", label: "Reports", icon: FileText },
  { key: "copilot", label: "AI Copilot", icon: Sparkles },
  { key: "graph", label: "Dependency Graph", icon: Network },
  { key: "agility", label: "Agility Score", icon: BarChart3 },
  { key: "blast", label: "Blast Radius", icon: Zap },
  { key: "validation", label: "PQC Validation", icon: Shield },
  { key: "remediation", label: "Remediation Plan", icon: GitBranch },
  { key: "tickets", label: "Migration Tickets", icon: Ticket },
  { key: "cicd", label: "CI/CD Gate", icon: GitMerge },
];

/* -------------------------------------------------------------------------
   Normalize a backend Finding into the shape the UI reads.
   Backend shape (app/models/schemas.py::Finding):
     file_path, line_number, matched_pattern, quantum_harvest_now_risk,
     artifact_type, criticality, exposure, mosca
------------------------------------------------------------------------- */
function normalizeFinding(f) {
  return {
    id: f.id,
    severity: f.severity,
    category: f.category,
    title: f.title,
    description: f.description,
    file: f.file_path,
    line: f.line_number,
    rule: f.matched_pattern,
    harvest: f.quantum_harvest_now_risk,
    remediation: f.remediation,
    nist_pqc_recommendation: f.nist_pqc_recommendation,
    artifactType: f.artifact_type,
    criticality: f.criticality,
    exposure: f.exposure,
    mosca: f.mosca,
    extra: f.extra || {},
  };
}

/* -------------------------------------------------------------------------
   Shared building blocks
------------------------------------------------------------------------- */
function Panel({ title, description, children, style = {}, right = null }) {
  return (
    <div className="rounded-lg" style={{ background: C.panel, border: `1px solid ${C.border}`, ...style }}>
      {(title || description) && (
        <div className="flex items-start justify-between px-5 pt-4 pb-3" style={{ borderBottom: `1px solid ${C.border}` }}>
          <div>
            {title && <h3 className="text-[13px] font-semibold" style={{ color: C.text, fontFamily: FONT }}>{title}</h3>}
            {description && <p className="text-[12px] mt-0.5" style={{ color: C.textMuted }}>{description}</p>}
          </div>
          {right}
        </div>
      )}
      <div className="px-5 py-4">{children}</div>
    </div>
  );
}
function SeverityDot({ severity }) {
  return <span className="inline-block w-2 h-2 rounded-full shrink-0" style={{ background: SEVERITY_COLOR[severity] }} />;
}

/* Renders markdown as properly styled elements instead of dumping raw
   '#'/'**'/'-' syntax as plain text — used for every report, the migration
   roadmap, and AI copilot replies. */
function Markdown({ children }) {
  return (
    <div className="text-[13px] leading-relaxed" style={{ color: C.textMuted, fontFamily: FONT }}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h1: ({ node, ...p }) => <h1 className="text-[19px] font-bold mt-1 mb-2" style={{ color: C.text, fontFamily: FONT }} {...p} />,
          h2: ({ node, ...p }) => <h2 className="text-[16px] font-bold mt-4 mb-2" style={{ color: C.text, fontFamily: FONT }} {...p} />,
          h3: ({ node, ...p }) => <h3 className="text-[14px] font-semibold mt-3 mb-1.5" style={{ color: C.accent, fontFamily: FONT }} {...p} />,
          p: ({ node, ...p2 }) => <p className="mb-2.5" {...p2} />,
          strong: ({ node, ...p }) => <strong style={{ color: C.text, fontWeight: 600 }} {...p} />,
          em: ({ node, ...p }) => <em style={{ color: C.textFaint }} {...p} />,
          ul: ({ node, ...p }) => <ul className="list-disc pl-5 mb-2.5 flex flex-col gap-1" {...p} />,
          ol: ({ node, ...p }) => <ol className="list-decimal pl-5 mb-2.5 flex flex-col gap-1" {...p} />,
          li: ({ node, ...p }) => <li {...p} />,
          code: ({ node, inline, ...p }) =>
            inline ? (
              <code className="px-1 py-0.5 rounded text-[12px]" style={{ background: C.panelRaised, color: C.accent, fontFamily: MONO }} {...p} />
            ) : (
              <code className="block p-3 rounded text-[12px] overflow-x-auto mb-2.5" style={{ background: C.panelRaised, color: C.text, fontFamily: MONO }} {...p} />
            ),
          table: ({ node, ...p }) => <table className="w-full text-[12px] mb-2.5 border-collapse" {...p} />,
          th: ({ node, ...p }) => <th className="text-left py-1.5 px-2 font-semibold" style={{ color: C.text, borderBottom: `1px solid ${C.border}` }} {...p} />,
          td: ({ node, ...p }) => <td className="py-1.5 px-2" style={{ borderBottom: `1px solid ${C.border}` }} {...p} />,
          hr: () => <hr className="my-3" style={{ borderColor: C.border }} />,
          a: ({ node, ...p }) => <a style={{ color: C.accent }} target="_blank" rel="noreferrer" {...p} />,
        }}
      >
        {children}
      </ReactMarkdown>
    </div>
  );
}
function StatRow({ label, value, max = 100, accent, description }) {
  const pct = Math.round((value / max) * 100);
  return (
    <div className="py-2.5" style={{ borderBottom: `1px solid ${C.border}` }}>
      <div className="flex items-baseline justify-between mb-1.5">
        <span className="text-[12px]" style={{ color: C.textMuted }}>{label}</span>
        <span className="text-[15px] font-semibold" style={{ color: C.text, fontFamily: MONO }}>{value}<span style={{ color: C.textFaint, fontSize: 11 }}>/100</span></span>
      </div>
      <div className="w-full h-1.5 rounded-full" style={{ background: C.accentDim }}>
        <div className="h-1.5 rounded-full" style={{ width: `${pct}%`, background: accent }} />
      </div>
      {description && <p className="text-[11px] mt-1.5" style={{ color: C.textFaint }}>{description}</p>}
    </div>
  );
}

export function normalizeApiBase(url) {
  if (!url) return "http://localhost:8000/api/v1";
  let clean = url.trim().replace(/\/+$/, "");
  if (!clean.endsWith("/api/v1")) {
    clean += "/api/v1";
  }
  return clean;
}

/* -------------------------------------------------------------------------
   Connection indicator — pings /health so the person can tell at a glance
   whether the backend is actually reachable, instead of guessing.
------------------------------------------------------------------------- */
function useBackendStatus(apiBase) {
  const [status, setStatus] = useState("checking"); // checking | ok | down
  useEffect(() => {
    let cancelled = false;
    setStatus("checking");
    const normalized = normalizeApiBase(apiBase);
    const rootUrl = normalized.replace(/\/api\/v1$/, "");

    // Try /api/v1/health first, fallback to root /health
    fetch(`${normalized}/health`)
      .then((r) => {
        if (!cancelled) {
          if (r.ok) setStatus("ok");
          else throw new Error("not ok");
        }
      })
      .catch(() => {
        fetch(`${rootUrl}/health`)
          .then((r2) => { if (!cancelled) setStatus(r2.ok ? "ok" : "down"); })
          .catch(() => { if (!cancelled) setStatus("down"); });
      });
    return () => { cancelled = true; };
  }, [apiBase]);
  return status;
}

/* -------------------------------------------------------------------------
   Upload screen — the empty state. Shown until a real scan exists.
------------------------------------------------------------------------- */
function UploadScreen({ apiBase, setApiBase, onScanComplete }) {
  const [dragOver, setDragOver] = useState(false);
  const [file, setFile] = useState(null);
  const [targetName, setTargetName] = useState("");
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState(null);
  const [showSettings, setShowSettings] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [threatHorizon, setThreatHorizon] = useState(10);
  const [classConfigFile, setClassConfigFile] = useState(null);
  const inputRef = useRef(null);
  const classConfigRef = useRef(null);
  const status = useBackendStatus(apiBase);

  function pickFile(f) {
    if (!f) return;
    if (!f.name.endsWith(".zip") && !f.name.endsWith(".tar")) {
      setError("Only .zip (source code) or .tar (docker save image) files are supported.");
      return;
    }
    setError(null);
    setFile(f);
    if (!targetName) setTargetName(f.name.replace(/\.(zip|tar)$/, ""));
  }

  async function runScan() {
    if (!file) return;
    setUploading(true);
    setError(null);
    try {
      const form = new FormData();
      form.append("file", file);
      if (classConfigFile) form.append("classification_config", classConfigFile);
      const params = new URLSearchParams({
        target_name: targetName || "uploaded-project",
        quantum_threat_horizon_years: String(threatHorizon),
      });
      const base = normalizeApiBase(apiBase);
      const url = `${base}/scans/upload?${params.toString()}`;
      const res = await fetch(url, { method: "POST", body: form });
      if (!res.ok) {
        const body = await res.text();
        throw new Error(`Server responded ${res.status}: ${body.slice(0, 200)}`);
      }
      const data = await res.json();
      onScanComplete(data);
    } catch (e) {
      if (e instanceof TypeError) {
        setError(
          `Couldn't reach the backend at ${apiBase}. Make sure it's running ` +
          `(uvicorn app.main:app --reload) and that this page's origin is allowed in CORS.`
        );
      } else {
        setError(e.message);
      }
    } finally {
      setUploading(false);
    }
  }

  return (
    <div className="relative min-h-screen w-full flex items-center justify-center py-10" style={{ background: "transparent", fontFamily: FONT }}>
      <BackgroundVideo src="/bg-video.mp4" overlayOpacity={0.75} />
      <div className="w-full max-w-lg relative z-10">
        <div className="flex items-center gap-2 justify-center mb-1">
          <div className="w-7 h-7 rounded flex items-center justify-center" style={{ background: C.accent }}>
            <ShieldCheck size={16} color="#0C0E12" strokeWidth={2.5} />
          </div>
          <span className="text-[15px] font-semibold" style={{ color: C.text }}>QuantumShield</span>
        </div>
        <p className="text-center text-[12px] mb-6" style={{ color: C.textFaint }}>
          Upload source code or a container image to scan for security and quantum-readiness issues.
        </p>

        {/* Backend connection status */}
        <div className="flex items-center justify-between mb-3 px-1">
          <div className="flex items-center gap-1.5 text-[11px]" style={{ color: status === "ok" ? C.low : status === "down" ? C.critical : C.textFaint }}>
            {status === "checking" && <Loader2 size={12} className="animate-spin" />}
            {status === "ok" && <CheckCircle2 size={12} />}
            {status === "down" && <AlertCircle size={12} />}
            {status === "checking" && "Checking backend connection…"}
            {status === "ok" && `Connected to ${apiBase}`}
            {status === "down" && `Can't reach ${apiBase}`}
          </div>
          <button onClick={() => setShowSettings((s) => !s)} className="flex items-center gap-1 text-[11px]" style={{ color: C.textFaint }}>
            <Settings2 size={12} /> Change
          </button>
        </div>
        {showSettings && (
          <div className="mb-4 p-3 rounded" style={{ background: C.panelRaised, border: `1px solid ${C.border}` }}>
            <label className="text-[11px] block mb-1" style={{ color: C.textMuted }}>Backend API URL</label>
            <input
              value={apiBase}
              onChange={(e) => setApiBase(e.target.value)}
              className="w-full bg-transparent text-[12px] px-2 py-1.5 rounded outline-none"
              style={{ color: C.text, border: `1px solid ${C.border}`, fontFamily: MONO }}
            />
          </div>
        )}

        {/* Dropzone */}
        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => { e.preventDefault(); setDragOver(false); pickFile(e.dataTransfer.files[0]); }}
          onClick={() => inputRef.current?.click()}
          className="rounded-lg flex flex-col items-center justify-center py-10 cursor-pointer transition-colors"
          style={{
            border: `1.5px dashed ${dragOver ? C.accent : C.border}`,
            background: dragOver ? C.accentDim : C.panel,
          }}
        >
          <input ref={inputRef} type="file" accept=".zip,.tar" className="hidden" onChange={(e) => pickFile(e.target.files[0])} />
          <UploadCloud size={22} color={C.textMuted} />
          <p className="text-[13px] mt-3" style={{ color: C.text }}>
            {file ? file.name : "Drop a .zip (source) or .tar (docker save image) here, or click to browse"}
          </p>
          <p className="text-[11px] mt-1" style={{ color: C.textFaint }}>
            .zip: source code, certs, Dockerfiles, dependency manifests  ·  .tar: output of `docker save -o image.tar`
          </p>
        </div>

        {file && (
          <div className="mt-4">
            <label className="text-[11px] block mb-1" style={{ color: C.textMuted }}>Project name</label>
            <input
              value={targetName}
              onChange={(e) => setTargetName(e.target.value)}
              className="w-full bg-transparent text-[13px] px-3 py-2 rounded outline-none"
              style={{ color: C.text, border: `1px solid ${C.border}` }}
            />
          </div>
        )}

        <button onClick={() => setShowAdvanced((s) => !s)} className="flex items-center gap-1 text-[11px] mt-4" style={{ color: C.textFaint }}>
          <Settings2 size={12} /> Advanced: risk assumptions {showAdvanced ? "▲" : "▼"}
        </button>
        {showAdvanced && (
          <div className="mt-2 p-3 rounded flex flex-col gap-3" style={{ background: C.panelRaised, border: `1px solid ${C.border}` }}>
            <div>
              <label className="text-[11px] block mb-1" style={{ color: C.textMuted }}>
                Quantum threat horizon (Z) — years until a cryptographically relevant quantum computer is expected
              </label>
              <input
                type="number" min="1" max="50" value={threatHorizon}
                onChange={(e) => setThreatHorizon(e.target.value)}
                className="w-24 bg-transparent text-[13px] px-2 py-1.5 rounded outline-none"
                style={{ color: C.text, border: `1px solid ${C.border}`, fontFamily: MONO }}
              />
              <p className="text-[10.5px] mt-1" style={{ color: C.textFaint }}>
                Used in Mosca's inequality (X+Y &gt; Z) to flag assets at risk. Default 10 — override with your own risk register's estimate.
              </p>
            </div>
            <div>
              <label className="text-[11px] block mb-1" style={{ color: C.textMuted }}>
                Business criticality config (optional JSON)
              </label>
              <button
                onClick={() => classConfigRef.current?.click()}
                className="text-[11px] px-2.5 py-1.5 rounded"
                style={{ border: `1px solid ${C.border}`, color: classConfigFile ? C.low : C.textMuted }}
              >
                {classConfigFile ? classConfigFile.name : "Upload path→criticality map"}
              </button>
              <input ref={classConfigRef} type="file" accept=".json" className="hidden" onChange={(e) => setClassConfigFile(e.target.files[0])} />
              <p className="text-[10.5px] mt-1" style={{ color: C.textFaint }}>
                {'{ "path_criticality": { "services/payments": "critical" }, "default": "medium" }'} — overrides the built-in path heuristics.
              </p>
            </div>
          </div>
        )}

        {error && (
          <div className="mt-4 p-3 rounded flex gap-2 items-start" style={{ background: "#2A1418", border: `1px solid ${C.critical}55` }}>
            <AlertCircle size={14} color={C.critical} className="shrink-0 mt-0.5" />
            <p className="text-[12px] leading-relaxed" style={{ color: C.text }}>{error}</p>
          </div>
        )}

        <button
          onClick={runScan}
          disabled={!file || uploading}
          className="w-full mt-4 py-2.5 rounded text-[13px] font-medium flex items-center justify-center gap-2"
          style={{
            background: !file || uploading ? C.panelRaised : C.accent,
            color: !file || uploading ? C.textFaint : "#0C0E12",
            cursor: !file || uploading ? "not-allowed" : "pointer",
          }}
        >
          {uploading ? <><Loader2 size={14} className="animate-spin" /> Scanning…</> : "Run scan"}
        </button>

        <p className="text-[11px] text-center mt-4" style={{ color: C.textFaint }}>
          No project handy? Zip <code style={{ fontFamily: MONO }}>backend/app/scanners/samples/demo_target</code> from
          the repo — it's a real sample vulnerable project built to test this scanner.
        </p>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------
   Overview page
------------------------------------------------------------------------- */
function OverviewPage({ scan, history, findings }) {
  const s = scan?.scores || {
    overall_health: 0,
    grade: "F",
    risk_trend: "stable",
    security_score: 0,
    quantum_readiness_score: 0,
    compliance_score: 0,
  };
  const gaugeData = [{ value: s.overall_health ?? 0 }];
  const total = scan?.total_findings ?? 0;
  const sevMap = scan?.findings_by_severity || {};
  const criticalCount = sevMap.critical || 0;

  const trendData = Array.isArray(history)
    ? history
        .filter((h) => h && h.scores && h.completed_at)
        .map((h) => ({
          scan: new Date(h.completed_at).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
          health: h.scores?.overall_health ?? 0,
        }))
    : [];

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-12 gap-4">
        <Panel style={{ gridColumn: "span 4" }} title="Overall Security Health" description="A single weighted score combining today's exposure and post-quantum exposure.">
          <div className="flex items-center gap-4">
            <div className="w-24 h-24 relative shrink-0">
              <ResponsiveContainer width="100%" height="100%">
                <RadialBarChart innerRadius="76%" outerRadius="100%" data={gaugeData} startAngle={90} endAngle={-270}>
                  <RadialBar dataKey="value" cornerRadius={8} fill={C.accent} background={{ fill: C.accentDim }} max={100} />
                </RadialBarChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex items-center justify-center">
                <span className="text-xl font-bold" style={{ color: C.text, fontFamily: MONO }}>{s.overall_health}</span>
              </div>
            </div>
            <div>
              <span className="text-2xl font-bold" style={{ color: C.text, fontFamily: MONO }}>Grade {s.grade}</span>
              <div className="flex items-center gap-1.5 text-[12px] mt-1" style={{ color: s.risk_trend === "declining" ? C.critical : s.risk_trend === "improving" ? C.low : C.textMuted }}>
                <span>{s.risk_trend === "declining" ? "▾" : s.risk_trend === "improving" ? "▴" : "—"}</span>
                <span>{s.risk_trend} vs. prior scan</span>
              </div>
              {criticalCount > 0 && (
                <p className="text-[11px] mt-2 max-w-[180px]" style={{ color: C.textFaint }}>
                  {criticalCount} critical finding{criticalCount !== 1 ? "s" : ""} driving the score down — see Findings.
                </p>
              )}
            </div>
          </div>
        </Panel>

        <Panel style={{ gridColumn: "span 4" }} title="Score breakdown" description="What's feeding into the overall number.">
          <StatRow label="Security score" value={s.security_score} accent={C.accent} description="Exposure to known attack techniques usable today." />
          <StatRow label="Quantum readiness" value={s.quantum_readiness_score} accent={C.accent} description="Exposure once large-scale quantum computers exist." />
          <StatRow label="Compliance score" value={s.compliance_score} accent={C.accent} description="Rough alignment with SOC 2 / PCI-DSS / NIST controls." />
        </Panel>

        <Panel style={{ gridColumn: "span 4" }} title="Open findings" description={`${total} total across ${scan.files_scanned} files scanned.`}>
          {total > 0 ? (
            <>
              <div className="w-full h-3 rounded-full overflow-hidden flex mb-3" style={{ background: C.accentDim }}>
                {Object.entries(scan.findings_by_severity).map(([sev, count]) => (
                  <div key={sev} style={{ width: `${(count / total) * 100}%`, background: SEVERITY_COLOR[sev] }} title={`${sev}: ${count}`} />
                ))}
              </div>
              <div className="flex flex-col gap-1.5">
                {Object.entries(scan.findings_by_severity).map(([sev, count]) => (
                  <div key={sev} className="flex items-center justify-between text-[12px]">
                    <div className="flex items-center gap-2"><SeverityDot severity={sev} /><span className="capitalize" style={{ color: C.textMuted }}>{sev}</span></div>
                    <span style={{ color: C.text, fontFamily: MONO }}>{count}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <p className="text-[12px]" style={{ color: C.low }}>No findings detected in this scan.</p>
          )}
        </Panel>
      </div>

      <Panel title="Health trend" description="Overall Security Health across scans you've run this session.">
        {trendData.length > 1 ? (
          <ResponsiveContainer width="100%" height={160}>
            <AreaChart data={trendData} margin={{ left: -20 }}>
              <defs>
                <linearGradient id="healthFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={C.accent} stopOpacity={0.35} />
                  <stop offset="100%" stopColor={C.accent} stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="2 4" stroke={C.border} vertical={false} />
              <XAxis dataKey="scan" stroke={C.textFaint} tick={{ fontSize: 11, fontFamily: MONO }} axisLine={{ stroke: C.border }} tickLine={false} />
              <YAxis stroke={C.textFaint} tick={{ fontSize: 11, fontFamily: MONO }} domain={[0, 100]} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: C.panelRaised, border: `1px solid ${C.border}`, borderRadius: 6, fontSize: 12, fontFamily: FONT }} />
              <Area type="monotone" dataKey="health" stroke={C.accent} strokeWidth={2} fill="url(#healthFill)" />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <p className="text-[12px]" style={{ color: C.textFaint }}>
            Run another scan (even of the same project) to start tracking how this score changes over time.
          </p>
        )}
      </Panel>

      <div className="grid grid-cols-12 gap-4">
        <Panel style={{ gridColumn: "span 4" }} title="Mosca's Inequality" description="X (data lifetime) + Y (migration time) vs. Z (quantum threat horizon).">
          {scan.mosca_at_risk_count > 0 ? (
            <div className="flex items-center gap-3">
              <div className="w-11 h-11 rounded-full flex items-center justify-center shrink-0" style={{ background: `#${MOSCA_COLOR.at_risk}1A` }}>
                <AlertCircle size={20} color={`#${MOSCA_COLOR.at_risk}`} />
              </div>
              <div>
                <p className="text-[20px] font-bold" style={{ color: C.text, fontFamily: MONO }}>{scan.mosca_at_risk_count}</p>
                <p className="text-[11px]" style={{ color: C.textFaint }}>asset{scan.mosca_at_risk_count !== 1 ? "s" : ""} where X+Y exceeds Z — see Quantum Readiness for detail.</p>
              </div>
            </div>
          ) : (
            <p className="text-[12px]" style={{ color: C.low }}>No assets currently exceed the quantum threat horizon under these assumptions.</p>
          )}
        </Panel>

        <Panel style={{ gridColumn: "span 4" }} title="By business criticality" description="How findings distribute across asset importance.">
          {Object.keys(scan.findings_by_criticality || {}).length > 0 ? (
            <div className="flex flex-col gap-1.5">
              {["critical", "high", "medium", "low"].filter((c) => scan.findings_by_criticality[c]).map((c) => (
                <div key={c} className="flex items-center justify-between text-[12px]">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full" style={{ background: `#${CRITICALITY_COLOR[c]}` }} />
                    <span className="capitalize" style={{ color: C.textMuted }}>{c}</span>
                  </div>
                  <span style={{ color: C.text, fontFamily: MONO }}>{scan.findings_by_criticality[c]}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-[12px]" style={{ color: C.textFaint }}>No criticality data.</p>
          )}
        </Panel>

        <Panel style={{ gridColumn: "span 4" }} title="Asset types found" description="Cryptographic Bill of Materials breakdown — see Asset Inventory tab.">
          <div className="flex flex-col gap-1.5">
            {Object.entries(scan.findings_by_artifact_type || {}).map(([type, count]) => (
              <div key={type} className="flex items-center justify-between text-[12px]">
                <span className="capitalize" style={{ color: C.textMuted }}>{type.replace(/-/g, " ")}</span>
                <span style={{ color: C.text, fontFamily: MONO }}>{count}</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------
   Findings page
------------------------------------------------------------------------- */
function FindingsPage({ findings, selectedForSimulation, onToggleSimulate }) {
  const [filter, setFilter] = useState("all");
  const [expanded, setExpanded] = useState(null);
  const filtered = useMemo(() => (filter === "all" ? findings : findings.filter((f) => f.severity === filter)), [filter, findings]);

  if (findings.length === 0) {
    return <Panel title="Findings" description="Nothing to show yet."><p className="text-[12px]" style={{ color: C.low }}>This scan found no issues.</p></Panel>;
  }

  return (
    <Panel
      title="Findings"
      description="Every issue this scan detected, in the exact file and line it was found. Click a row to see why it matters and how to fix it."
      right={
        <div className="flex gap-1">
          {["all", "critical", "high", "medium", "low"].map((s) => (
            <button key={s} onClick={() => setFilter(s)} className="text-[11px] px-2.5 py-1 rounded capitalize"
              style={{ background: filter === s ? C.accentDim : "transparent", color: filter === s ? C.accent : C.textMuted, border: `1px solid ${filter === s ? C.accent : "transparent"}` }}>
              {s}
            </button>
          ))}
        </div>
      }
    >
      <div className="flex flex-col">
        {filtered.map((f) => {
          const Icon = CATEGORY_ICON[f.category] || Bug;
          const isOpen = expanded === f.id;
          const isSelected = selectedForSimulation?.has(f.id);
          return (
            <div key={f.id} style={{ borderBottom: `1px solid ${C.border}` }}>
              <div className="w-full flex items-center gap-3 py-3 text-left">
                <input
                  type="checkbox"
                  checked={isSelected || false}
                  onChange={() => onToggleSimulate && onToggleSimulate(f.id)}
                  className="rounded cursor-pointer shrink-0"
                  style={{ accentColor: C.accent }}
                  title="Include in simulation"
                />
                <div className="w-1 self-stretch rounded-full shrink-0" style={{ background: SEVERITY_COLOR[f.severity] }} />
                <button onClick={() => setExpanded(isOpen ? null : f.id)} className="flex-1 min-w-0 flex items-center gap-3 text-left">
                  <Icon size={16} color={C.textMuted} className="shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-[13.5px] font-medium truncate" style={{ color: C.text }}>{f.title}</p>
                    <p className="text-[11px] truncate mt-0.5" style={{ color: C.textFaint, fontFamily: MONO }}>{f.file}{f.line ? `:${f.line}` : ""}</p>
                    <div className="flex items-center gap-1.5 mt-1.5 flex-wrap">
                      {f.criticality && (
                        <span className="text-[9.5px] uppercase font-semibold px-1.5 py-0.5 rounded" style={{ color: `#${CRITICALITY_COLOR[f.criticality]}`, background: `#${CRITICALITY_COLOR[f.criticality]}1A` }}>
                          {f.criticality}
                        </span>
                      )}
                      {f.harvest && <span className="text-[9.5px] px-1.5 py-0.5 rounded" style={{ color: C.accent, background: C.accentDim, fontFamily: MONO }}>harvest-now-risk</span>}
                    </div>
                  </div>
                  <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded shrink-0" style={{ color: SEVERITY_COLOR[f.severity] }}>{f.severity}</span>
                  <ChevronDown size={14} color={C.textFaint} style={{ transform: isOpen ? "rotate(180deg)" : "none", transition: "transform 0.15s" }} />
                </button>
              </div>
              {isOpen && (
                <div className="pb-4 pl-12 pr-3 flex flex-col gap-3">
                  <div><p className="text-[10.5px] uppercase tracking-wide font-semibold mb-1" style={{ color: C.textFaint }}>Why this matters</p><p className="text-[13px] leading-relaxed" style={{ color: C.textMuted }}>{f.description}</p></div>
                  <div><p className="text-[10.5px] uppercase tracking-wide font-semibold mb-1" style={{ color: C.textFaint }}>How to fix it</p><p className="text-[13px] leading-relaxed" style={{ color: C.textMuted }}>{f.remediation}</p></div>
                  {f.mosca && (
                    <div>
                      <p className="text-[10.5px] uppercase tracking-wide font-semibold mb-1" style={{ color: `#${MOSCA_COLOR[f.mosca.risk_level]}` }}>Mosca's inequality — {f.mosca.risk_level.replace("_", " ")}</p>
                      <p className="text-[13px] leading-relaxed" style={{ color: C.textMuted }}>{f.mosca.rationale}</p>
                    </div>
                  )}
                  <p className="text-[10.5px]" style={{ color: C.textFaint, fontFamily: MONO }}>rule: {f.rule}</p>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

/* -------------------------------------------------------------------------
   Asset Inventory page (CBOM view)
------------------------------------------------------------------------- */
function InventoryPage({ scan, findings, apiBase, selectedForSimulation, onToggleSimulate }) {
  const [typeFilter, setTypeFilter] = useState("all");
  const [exportError, setExportError] = useState(null);
  const [exporting, setExporting] = useState(false);

  const types = ["all", ...Object.keys(scan.findings_by_artifact_type || {})];
  const filtered = typeFilter === "all" ? findings : findings.filter((f) => f.artifactType === typeFilter);

  async function exportCbom() {
    setExporting(true);
    setExportError(null);
    try {
      const base = normalizeApiBase(apiBase);
      const res = await fetch(`${base}/scans/${scan.scan_id}/cbom`);
      if (!res.ok) throw new Error(await res.text());
      const cbom = await res.json();
      const blob = new Blob([JSON.stringify(cbom, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${scan.target_name}-cbom.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setExportError("Couldn't export CBOM: " + e.message);
    } finally {
      setExporting(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <Panel title="What this page shows">
        <p className="text-[12px] leading-relaxed" style={{ color: C.textMuted }}>
          Every cryptographic artifact this scan catalogued — algorithms, certificates, protocols, keys/secrets,
          libraries, and hardware/cloud key-management usage — in one inventory. This is the "discovery and
          inventory" step a PQC migration has to start from. Export it as a standardized{" "}
          <span style={{ fontFamily: MONO, color: C.text }}>CycloneDX 1.6</span> Cryptographic Bill of Materials
          (CBOM) to feed into other tooling.
        </p>
      </Panel>

      <Panel title="Asset Catalogue" description={`${findings.length} artifacts across ${types.length - 1} types.`}>
        <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
          <div className="flex gap-1 flex-wrap">
            {types.map((t) => (
              <button key={t} onClick={() => setTypeFilter(t)} className="text-[11px] px-2.5 py-1 rounded capitalize"
                style={{ background: typeFilter === t ? C.accentDim : "transparent", color: typeFilter === t ? C.accent : C.textMuted, border: `1px solid ${typeFilter === t ? C.accent : C.border}` }}>
                {t.replace(/-/g, " ")}
              </button>
            ))}
          </div>
          <button onClick={exportCbom} disabled={exporting} className="flex items-center gap-1.5 text-[11px] px-3 py-1.5 rounded shrink-0" style={{ color: C.accent, background: C.accentDim }}>
            {exporting ? <Loader2 size={12} className="animate-spin" /> : <Download size={12} />} Export CBOM
          </button>
        </div>
        {exportError && <p className="text-[12px] mb-3" style={{ color: C.critical }}>{exportError}</p>}
        <div className="flex flex-col">
          {filtered.map((f) => {
            const ExposureIcon = EXPOSURE_ICON[f.exposure] || HelpCircle;
            const Icon = CATEGORY_ICON[f.category] || Bug;
            const isSelected = selectedForSimulation?.has(f.id);
            return (
              <div key={f.id} className="flex items-center gap-3 py-3" style={{ borderBottom: `1px solid ${C.border}` }}>
                <input
                  type="checkbox"
                  checked={isSelected || false}
                  onChange={() => onToggleSimulate && onToggleSimulate(f.id)}
                  className="rounded cursor-pointer shrink-0"
                  style={{ accentColor: C.accent }}
                  title="Include in simulation"
                />
                <Icon size={15} color={C.textMuted} className="shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-[13px] font-medium truncate" style={{ color: C.text }}>{f.title}</p>
                  <p className="text-[10.5px] truncate mt-0.5" style={{ color: C.textFaint, fontFamily: MONO }}>{f.file}{f.line ? `:${f.line}` : ""}</p>
                  <div className="flex items-center gap-1.5 mt-1.5 flex-wrap">
                    <span className="text-[9.5px] px-1.5 py-0.5 rounded capitalize" style={{ color: C.textMuted, border: `1px solid ${C.border}` }}>
                      {f.artifactType?.replace(/-/g, " ")}
                    </span>
                    {f.criticality && (
                      <span className="text-[9.5px] uppercase font-semibold px-1.5 py-0.5 rounded" style={{ color: `#${CRITICALITY_COLOR[f.criticality]}`, background: `#${CRITICALITY_COLOR[f.criticality]}1A` }}>
                        {f.criticality}
                      </span>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <div title={`Exposure: ${f.exposure}`}>
                    <ExposureIcon size={14} color={C.textFaint} />
                  </div>
                  {f.mosca && (
                    <span className="text-[9.5px] uppercase font-semibold px-1.5 py-0.5 rounded whitespace-nowrap" style={{ color: `#${MOSCA_COLOR[f.mosca.risk_level]}`, background: `#${MOSCA_COLOR[f.mosca.risk_level]}1A` }}>
                      {f.mosca.risk_level.replace("_", " ")}
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </Panel>
    </div>
  );
}

/* -------------------------------------------------------------------------
   Quantum Readiness page
------------------------------------------------------------------------- */
function QuantumPage({ scan, findings, apiBase }) {
  const quantumFindings = findings.filter((f) => f.category === "quantum_vulnerable_crypto");
  const [roadmap, setRoadmap] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function fetchRoadmap() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${apiBase}/scans/${scan.scan_id}/roadmap`);
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setRoadmap(data.roadmap);
    } catch (e) {
      setError("Couldn't generate the roadmap. This needs ANTHROPIC_API_KEY set on the backend.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <Panel title="What this page shows">
        <p className="text-[12px] leading-relaxed" style={{ color: C.textMuted }}>
          Algorithms like RSA and elliptic-curve cryptography (ECC/ECDSA) are secure against today's
          computers but would be broken by a large enough quantum computer running Shor's algorithm.
          The risk isn't only future — an attacker can capture encrypted traffic <em>today</em> and
          decrypt it later once that hardware exists. This is called "harvest now, decrypt later."
        </p>
      </Panel>

      {quantumFindings.length === 0 ? (
        <Panel title="Quantum-vulnerable cryptography"><p className="text-[12px]" style={{ color: C.low }}>None detected in this scan.</p></Panel>
      ) : (
        <Panel title={`Quantum-vulnerable cryptography found (${quantumFindings.length})`} description="Each item maps to the NIST-standardized replacement to migrate toward.">
          <div className="flex flex-col gap-3">
            {quantumFindings.map((f) => (
              <div key={f.id} className="p-3 rounded-md" style={{ border: `1px solid ${C.border}`, background: C.panelRaised }}>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[13px] font-medium" style={{ color: C.text }}>{f.title}</span>
                  {f.harvest && <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ color: C.accent, background: C.accentDim, fontFamily: MONO }}>harvest-now-risk</span>}
                </div>
                <p className="text-[11px] mb-2" style={{ color: C.textFaint, fontFamily: MONO }}>{f.file}:{f.line}</p>
                <div className="flex items-center gap-2 text-[12px]">
                  <span style={{ color: C.textMuted }}>Migrate to:</span>
                  <span style={{ color: C.low, fontFamily: MONO }}>{f.nist_pqc_recommendation}</span>
                </div>
              </div>
            ))}
          </div>
        </Panel>
      )}

      <Panel title="Migration roadmap" description="AI-generated, phased plan grounded in the findings above.">
        {!roadmap && (
          <button onClick={fetchRoadmap} disabled={loading || quantumFindings.length === 0} className="text-[12px] px-3 py-1.5 rounded flex items-center gap-2"
            style={{ background: C.accentDim, color: C.accent, border: `1px solid ${C.accent}55`, opacity: quantumFindings.length === 0 ? 0.5 : 1 }}>
            {loading ? <><Loader2 size={13} className="animate-spin" /> Generating…</> : "Generate roadmap"}
          </button>
        )}
        {error && <p className="text-[12px] mt-2" style={{ color: C.critical }}>{error}</p>}
        {roadmap && <Markdown>{roadmap}</Markdown>}
      </Panel>
    </div>
  );
}

/* -------------------------------------------------------------------------
   Reports page
------------------------------------------------------------------------- */
const REPORT_TYPES = [
  { key: "executive", title: "Executive summary", desc: "One-page overview of scores and top risks, written for non-technical stakeholders.", icon: FileText },
  { key: "technical", title: "Technical findings report", desc: "Full list of every finding with file location, CWE reference, and remediation steps.", icon: FileText },
  { key: "migration-checklist", title: "Migration checklist", desc: "A checkbox list of every quantum-vulnerable item found, ready to track in a sprint board.", icon: ListChecks },
];

function ReportsPage({ scan, apiBase }) {
  const [active, setActive] = useState(null);
  const [content, setContent] = useState("");
  const [loading, setLoading] = useState(false);

  async function generate(key) {
    setActive(key);
    setLoading(true);
    setContent("");
    try {
      const base = normalizeApiBase(apiBase);
      const res = await fetch(`${base}/scans/${scan.scan_id}/reports/${key}`);
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setContent(data.content || data.markdown || "");
    } catch (e) {
      setContent(`Couldn't generate this report: ${e.message}`);
    } finally {
      setLoading(false);
    }
  }

  function download() {
    const blob = new Blob([content], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${scan.target_name}-${active}.md`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="flex flex-col gap-4">
      <Panel title="Reports" description="Generate a document from this scan's results. Each is built from the same underlying findings — pick the audience.">
        <div className="grid grid-cols-3 gap-3">
          {REPORT_TYPES.map((r) => (
            <div key={r.key} className="p-4 rounded-md flex flex-col" style={{ border: `1px solid ${C.border}`, background: C.panelRaised }}>
              <r.icon size={16} color={C.accent} />
              <p className="text-[13px] font-medium mt-2" style={{ color: C.text }}>{r.title}</p>
              <p className="text-[11px] mt-1 flex-1" style={{ color: C.textFaint }}>{r.desc}</p>
              <button onClick={() => generate(r.key)} className="text-[12px] mt-3 py-1.5 rounded" style={{ background: C.accentDim, color: C.accent, border: `1px solid ${C.accent}55` }}>
                Generate
              </button>
            </div>
          ))}
        </div>
      </Panel>

      {active && (
        <Panel
          title={REPORT_TYPES.find((r) => r.key === active)?.title}
          right={content && !loading ? (
            <button onClick={download} className="flex items-center gap-1.5 text-[11px] px-2.5 py-1 rounded" style={{ color: C.accent, background: C.accentDim }}>
              <Download size={12} /> Download .md
            </button>
          ) : null}
        >
          {loading ? (
            <div className="flex items-center gap-2 text-[12px]" style={{ color: C.textFaint }}><Loader2 size={13} className="animate-spin" /> Generating…</div>
          ) : (
            <div className="max-h-[420px] overflow-y-auto">
              <Markdown>{content}</Markdown>
            </div>
          )}
        </Panel>
      )}
    </div>
  );
}

/* -------------------------------------------------------------------------
   Copilot page
------------------------------------------------------------------------- */
function CopilotPage({ scan, apiBase }) {
  const [messages, setMessages] = useState([
    { role: "assistant", text: `I've read the results of the scan on ${scan.target_name}. Ask me anything about it.` },
  ]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);

  async function send() {
    if (!input.trim() || sending) return;
    const q = input.trim();
    setMessages((m) => [...m, { role: "user", text: q }]);
    setInput("");
    setSending(true);
    try {
      const base = normalizeApiBase(apiBase);
      const res = await fetch(`${base}/copilot/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scan_id: scan.scan_id, question: q }),
      });
      if (!res.ok) throw new Error();
      const data = await res.json();
      setMessages((m) => [...m, { role: "assistant", text: data.answer || data.reply }]);
    } catch {
      setMessages((m) => [...m, { role: "assistant", text: "I couldn't reach the AI advisor. This needs ANTHROPIC_API_KEY set on the backend — the scan data itself is fine, just the AI layer isn't configured." }]);
    } finally {
      setSending(false);
    }
  }

  return (
    <Panel title="AI Copilot" description="Answers are grounded only in this scan's actual findings." style={{ height: 460, display: "flex", flexDirection: "column" }}>
      <div className="flex-1 overflow-y-auto flex flex-col gap-3 pr-1">
        {messages.map((m, i) => (
          <div key={i} className="p-3 rounded-md max-w-[85%]"
            style={{ background: m.role === "assistant" ? C.panelRaised : C.accentDim, border: `1px solid ${C.border}`, alignSelf: m.role === "assistant" ? "flex-start" : "flex-end" }}>
            {m.role === "assistant" ? <Markdown>{m.text}</Markdown> : <p className="text-[12.5px] leading-relaxed" style={{ color: C.text }}>{m.text}</p>}
          </div>
        ))}
        {sending && <div className="text-[12px] flex items-center gap-2" style={{ color: C.textFaint }}><Loader2 size={12} className="animate-spin" /> Thinking…</div>}
      </div>
      <div className="flex items-center gap-2 mt-3 pt-3" style={{ borderTop: `1px solid ${C.border}` }}>
        <input value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => e.key === "Enter" && send()} placeholder="Ask about this scan…"
          className="flex-1 bg-transparent text-[13px] outline-none px-2 py-2 rounded" style={{ color: C.text, border: `1px solid ${C.border}` }} />
        <button onClick={send} aria-label="Send message" className="w-9 h-9 rounded flex items-center justify-center shrink-0" style={{ background: C.accent }}>
          <Send size={14} color="#0C0E12" />
        </button>
      </div>
    </Panel>
  );
}

/* -------------------------------------------------------------------------
   v0.2.0 Page Components (7 new views)
------------------------------------------------------------------------- */

function DependencyGraphPage({ scan, apiBase }) {
  const [graph, setGraph] = useState(scan?.dependency_graph || null);
  const [loading, setLoading] = useState(!scan?.dependency_graph);
  const [selectedNode, setSelectedNode] = useState(null);

  useEffect(() => {
    if (scan?.dependency_graph && scan.dependency_graph.nodes?.length) {
      setGraph(scan.dependency_graph);
      setLoading(false);
      return;
    }
    const base = normalizeApiBase(apiBase);
    fetch(`${base}/scans/${scan.scan_id}/dependency-graph`)
      .then((r) => r.json())
      .then((d) => {
        if (d && Array.isArray(d.nodes)) setGraph(d);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [scan.scan_id, scan.dependency_graph, apiBase]);

  if (loading) return <div className="p-8 text-center" style={{ color: C.textFaint }}><Loader2 className="animate-spin inline mr-2" size={16} /> Loading graph…</div>;
  const nodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const edges = Array.isArray(graph?.edges) ? graph.edges : [];
  if (nodes.length === 0) return <Panel title="Dependency Graph"><p className="text-[12px]" style={{ color: C.textFaint }}>No graph nodes available.</p></Panel>;

  const NODE_COLORS = {
    algorithm: "#EF4444", key: "#F59E0B", certificate: "#3B82F6",
    service: "#8B5CF6", library: "#10B981", file: "#6B7280", application: "#06B6D4",
  };

  return (
    <div className="flex flex-col gap-4">
      <Panel title="Crypto Dependency Graph" description="Graph map of algorithms, keys, certificates, services, libraries, and files.">
        <p className="text-[11px] mb-3 p-2 rounded" style={{ background: C.cardBg, border: `1px solid ${C.border}`, color: C.textFaint }}>
          ℹ️ {graph?.note || "Relationships are heuristically derived from static analysis."}
        </p>

        <div className="grid grid-cols-12 gap-4">
          <div className="col-span-8 p-4 rounded min-h-[400px] flex flex-col items-center justify-center relative overflow-hidden" style={{ background: C.cardBg, border: `1px solid ${C.border}` }}>
            <svg width="100%" height="380" viewBox="0 0 600 380" className="w-full h-full">
              <defs>
                <marker id="arrow" viewBox="0 0 10 10" refX="15" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill={C.border} />
                </marker>
              </defs>
              {edges.map((e, idx) => {
                const srcIdx = nodes.findIndex((n) => n.id === e.source);
                const tgtIdx = nodes.findIndex((n) => n.id === e.target);
                if (srcIdx === -1 || tgtIdx === -1) return null;
                const total = nodes.length;
                const x1 = 300 + 200 * Math.cos((2 * Math.PI * srcIdx) / total);
                const y1 = 190 + 140 * Math.sin((2 * Math.PI * srcIdx) / total);
                const x2 = 300 + 200 * Math.cos((2 * Math.PI * tgtIdx) / total);
                const y2 = 190 + 140 * Math.sin((2 * Math.PI * tgtIdx) / total);
                return (
                  <g key={idx}>
                    <line x1={x1} y1={y1} x2={x2} y2={y2} stroke={C.border} strokeWidth="1.5" strokeDasharray={e.heuristic ? "4" : undefined} markerEnd="url(#arrow)" />
                  </g>
                );
              })}
              {nodes.map((n, idx) => {
                const total = nodes.length;
                const cx = 300 + 200 * Math.cos((2 * Math.PI * idx) / total);
                const cy = 190 + 140 * Math.sin((2 * Math.PI * idx) / total);
                const isSelected = selectedNode?.id === n.id;
                const color = NODE_COLORS[n.node_type] || C.textMuted;
                return (
                  <g key={n.id} onClick={() => setSelectedNode(n)} className="cursor-pointer">
                    <circle cx={cx} cy={cy} r={isSelected ? 18 : 14} fill={color} stroke={isSelected ? "#FFF" : C.bg} strokeWidth={isSelected ? 3 : 2} />
                    <text x={cx} y={cy + 24} textAnchor="middle" fill={C.text} fontSize="9" fontFamily={MONO}>
                      {n.label.length > 18 ? n.label.substring(0, 16) + "…" : n.label}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          <div className="col-span-4 flex flex-col gap-3">
            <Panel title="Node Legend" style={{ padding: "12px" }}>
              <div className="flex flex-wrap gap-2 text-[11px]">
                {Object.entries(NODE_COLORS).map(([type, color]) => (
                  <div key={type} className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ background: color }} />
                    <span className="capitalize" style={{ color: C.textMuted }}>{type}</span>
                  </div>
                ))}
              </div>
            </Panel>

            <Panel title="Selected Node Detail" style={{ padding: "12px", minHeight: "220px" }}>
              {selectedNode ? (
                <div className="flex flex-col gap-2 text-[12px]">
                  <p className="font-semibold" style={{ color: C.text }}>{selectedNode.label}</p>
                  <p style={{ color: C.textFaint }}>Type: <strong style={{ color: C.text }}>{selectedNode.node_type}</strong></p>
                  {selectedNode.path && <p className="font-mono text-[11px]" style={{ color: C.textMuted }}>{selectedNode.path}</p>}
                </div>
              ) : (
                <p className="text-[12px]" style={{ color: C.textFaint }}>Click any node in the graph to view details.</p>
              )}
            </Panel>
          </div>
        </div>
      </Panel>
    </div>
  );
}

function AgilityPage({ scan, apiBase }) {
  const [data, setData] = useState(scan?.agility || null);
  const [loading, setLoading] = useState(!scan?.agility);

  useEffect(() => {
    if (scan?.agility) {
      setData(scan.agility);
      setLoading(false);
      return;
    }
    const base = normalizeApiBase(apiBase);
    fetch(`${base}/scans/${scan.scan_id}/agility`)
      .then((r) => r.json())
      .then((d) => {
        if (d && typeof d.score === "number") setData(d);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [scan.scan_id, scan.agility, apiBase]);

  if (loading) return <div className="p-8 text-center" style={{ color: C.textFaint }}><Loader2 className="animate-spin inline mr-2" size={16} /> Computing agility score…</div>;
  if (!data) return <Panel title="Cryptographic Agility Score"><p className="text-[12px]" style={{ color: C.textFaint }}>No agility data available.</p></Panel>;

  const factors = Array.isArray(data?.factors) ? data.factors : [];

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-12 gap-4">
        <Panel style={{ gridColumn: "span 4" }} title="Crypto Agility Score" description="Measures how hard it will be to swap cryptography out.">
          <div className="flex flex-col items-center justify-center p-4">
            <span className="text-4xl font-bold font-mono" style={{ color: data.score > 60 ? C.critical : data.score > 35 ? C.medium : C.low }}>
              {data.score}
            </span>
            <span className="text-[13px] font-semibold mt-1" style={{ color: C.text }}>
              Rating: {data.grade || "C"}
            </span>
            <p className="text-[11px] mt-3 text-center" style={{ color: C.textFaint }}>
              Score from 0 (easy to migrate) to 100 (extremely hard).
            </p>
          </div>
        </Panel>

        <Panel style={{ gridColumn: "span 8" }} title="Analysis Rationale" description="Explainable breakdown of factors driving the score.">
          <div className="text-[13px] leading-relaxed" style={{ color: C.text }}>
            <Markdown>{data.explanation || "No explanation available."}</Markdown>
          </div>
        </Panel>
      </div>

      <Panel title="Scoring Factor Breakdown" description="Detailed contribution of each code analysis factor.">
        <div className="flex flex-col gap-3">
          {factors.map((f) => (
            <div key={f.name} className="p-3 rounded flex flex-col gap-1" style={{ background: C.cardBg, border: `1px solid ${C.border}` }}>
              <div className="flex items-center justify-between">
                <span className="font-mono text-[12px] font-semibold" style={{ color: C.accent }}>{f.name}</span>
                <span className="font-mono text-[12px]" style={{ color: C.text }}>
                  +{(f.contribution || 0).toFixed(1)} / {f.weight} pts
                </span>
              </div>
              <p className="text-[12px]" style={{ color: C.textMuted }}>{f.note}</p>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function BlastRadiusPage({ scan, apiBase }) {
  const [data, setData] = useState(scan?.blast_radii || []);
  const [loading, setLoading] = useState(!scan?.blast_radii);

  useEffect(() => {
    if (scan?.blast_radii && scan.blast_radii.length > 0) {
      setData(scan.blast_radii);
      setLoading(false);
      return;
    }
    const base = normalizeApiBase(apiBase);
    fetch(`${base}/scans/${scan.scan_id}/blast-radius`)
      .then((r) => r.json())
      .then((d) => {
        if (Array.isArray(d)) setData(d);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [scan.scan_id, scan.blast_radii, apiBase]);

  if (loading) return <div className="p-8 text-center" style={{ color: C.textFaint }}><Loader2 className="animate-spin inline mr-2" size={16} /> Computing blast radius…</div>;

  const RATING_COLOR = { Low: C.low, Medium: C.medium, High: C.critical };
  const items = Array.isArray(data) ? data : [];

  return (
    <div className="flex flex-col gap-4">
      <Panel title="Migration Blast Radius" description="Impact radius of migrating each cryptographic asset.">
        <div className="flex flex-col gap-3">
          {items.map((item) => (
            <div key={item.finding_id} className="p-3.5 rounded flex flex-col gap-2" style={{ background: C.cardBg, border: `1px solid ${C.border}` }}>
              <div className="flex items-center justify-between">
                <p className="text-[13px] font-semibold" style={{ color: C.text }}>{item.finding_title}</p>
                <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold" style={{ background: `${RATING_COLOR[item.rating] || C.textMuted}20`, color: RATING_COLOR[item.rating] || C.textMuted }}>
                  {item.rating} BLAST
                </span>
              </div>
              <p className="text-[12px]" style={{ color: C.textMuted }}>{item.detail}</p>
              <div className="flex items-center gap-4 text-[11px]" style={{ color: C.textFaint }}>
                <span>Direct dependents: <strong style={{ color: C.text }}>{item.direct_dependencies?.length || 0}</strong></span>
                <span>Indirect: <strong style={{ color: C.text }}>{item.indirect_dependencies?.length || 0}</strong></span>
                <span>Total affected nodes: <strong style={{ color: C.text }}>{item.total_affected}</strong></span>
              </div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function ValidationPage({ scan, apiBase }) {
  const [data, setData] = useState(scan?.pqc_validations || []);
  const [loading, setLoading] = useState(!scan?.pqc_validations);

  useEffect(() => {
    if (scan?.pqc_validations && scan.pqc_validations.length > 0) {
      setData(scan.pqc_validations);
      setLoading(false);
      return;
    }
    const base = normalizeApiBase(apiBase);
    fetch(`${base}/scans/${scan.scan_id}/pqc-validation`)
      .then((r) => r.json())
      .then((d) => {
        if (Array.isArray(d)) setData(d);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [scan.scan_id, scan.pqc_validations, apiBase]);

  if (loading) return <div className="p-8 text-center" style={{ color: C.textFaint }}><Loader2 className="animate-spin inline mr-2" size={16} /> Validating PQC feasibility…</div>;

  const STATUS_COLOR = {
    VALID: C.low, PARTIALLY_SUPPORTED: C.medium, BLOCKED: C.critical, NOT_APPLICABLE: C.textFaint,
  };
  const list = Array.isArray(data) ? data : [];

  return (
    <div className="flex flex-col gap-4">
      <Panel title="PQC / Hybrid Migration Validation" description="Feasibility assessment against current NIST standards and library roadmaps.">
        <div className="flex flex-col gap-3">
          {list.map((v) => (
            <div key={v.finding_id} className="p-3.5 rounded flex flex-col gap-2" style={{ background: C.cardBg, border: `1px solid ${C.border}` }}>
              <div className="flex items-center justify-between">
                <p className="text-[13px] font-semibold" style={{ color: C.text }}>{v.finding_title}</p>
                <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold" style={{ background: `${STATUS_COLOR[v.status] || C.textMuted}20`, color: STATUS_COLOR[v.status] || C.textMuted }}>
                  {v.status}
                </span>
              </div>

              {v.recommended_pqc && (
                <p className="text-[12px]" style={{ color: C.accent }}>
                  💡 Target: <strong>{v.recommended_pqc}</strong>
                </p>
              )}

              {v.reasons?.length > 0 && (
                <ul className="list-disc list-inside text-[11.5px] flex flex-col gap-0.5" style={{ color: C.textMuted }}>
                  {v.reasons.map((r, i) => <li key={i}>{r}</li>)}
                </ul>
              )}

              {v.library_support && (
                <p className="text-[11px] p-2 rounded" style={{ background: C.bg, border: `1px solid ${C.border}`, color: C.textFaint }}>
                  📦 {v.library_support}
                </p>
              )}
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function RemediationPage({ scan, apiBase }) {
  const [plan, setPlan] = useState(scan?.remediation_plan || null);
  const [loading, setLoading] = useState(!scan?.remediation_plan);

  useEffect(() => {
    if (scan?.remediation_plan) {
      setPlan(scan.remediation_plan);
      setLoading(false);
      return;
    }
    const base = normalizeApiBase(apiBase);
    fetch(`${base}/scans/${scan.scan_id}/remediation`)
      .then((r) => r.json())
      .then((d) => {
        if (d && Array.isArray(d.phases)) setPlan(d);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [scan.scan_id, scan.remediation_plan, apiBase]);

  if (loading) return <div className="p-8 text-center" style={{ color: C.textFaint }}><Loader2 className="animate-spin inline mr-2" size={16} /> Generating remediation plan…</div>;
  if (!plan) return <Panel title="Phased Remediation Plan"><p className="text-[12px]" style={{ color: C.textFaint }}>No remediation plan available.</p></Panel>;

  const phases = Array.isArray(plan?.phases) ? plan.phases : [];

  return (
    <div className="flex flex-col gap-4">
      <Panel title="Phased Migration Plan" description={`3-phase roadmap covering ${plan.total_findings_addressed || 0} finding(s) (~${plan.total_effort_hours || 0} total effort hours).`}>
        <div className="flex flex-col gap-6 mt-2">
          {phases.map((p) => (
            <div key={p.phase_number} className="flex flex-col gap-2">
              <div className="flex items-center justify-between pb-1" style={{ borderBottom: `1px solid ${C.border}` }}>
                <h4 className="text-[14px] font-bold" style={{ color: C.accent }}>
                  Phase {p.phase_number}: {p.name}
                </h4>
                <span className="text-[12px] font-mono" style={{ color: C.textMuted }}>{p.timeframe} · ~{p.total_effort_hours} hrs</span>
              </div>
              <p className="text-[12px]" style={{ color: C.textFaint }}>{p.description}</p>
              <div className="flex flex-col gap-2 mt-1">
                {(p.items || []).map((item) => (
                  <div key={item.finding_id} className="p-3 rounded text-[12px]" style={{ background: C.cardBg, border: `1px solid ${C.border}` }}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-semibold" style={{ color: C.text }}>#{item.priority} {item.finding_title}</span>
                      <span className="font-mono text-[11px]" style={{ color: C.textMuted }}>~{item.effort_hours_estimate}h</span>
                    </div>
                    <p style={{ color: C.textMuted }}>{item.rationale}</p>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function TicketsPage({ scan, apiBase }) {
  const [tickets, setTickets] = useState(scan?.tickets || []);
  const [loading, setLoading] = useState(!scan?.tickets);

  useEffect(() => {
    if (scan?.tickets && scan.tickets.length > 0) {
      setTickets(scan.tickets);
      setLoading(false);
      return;
    }
    const base = normalizeApiBase(apiBase);
    fetch(`${base}/scans/${scan.scan_id}/tickets`)
      .then((r) => r.json())
      .then((d) => {
        if (Array.isArray(d)) setTickets(d);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [scan.scan_id, scan.tickets, apiBase]);

  const handleExport = (fmt) => {
    const base = normalizeApiBase(apiBase);
    fetch(`${base}/scans/${scan.scan_id}/tickets/export?fmt=${fmt}`, { method: "POST" })
      .then((r) => r.json())
      .then((d) => {
        const text = fmt === "markdown" ? (d.content || d.markdown) : JSON.stringify(d.tickets || d, null, 2);
        const blob = new Blob([text], { type: fmt === "markdown" ? "text/markdown" : "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `migration_tickets.${fmt === "markdown" ? "md" : "json"}`;
        a.click();
      });
  };

  if (loading) return <div className="p-8 text-center" style={{ color: C.textFaint }}><Loader2 className="animate-spin inline mr-2" size={16} /> Generating migration tickets…</div>;
  const list = Array.isArray(tickets) ? tickets : [];

  return (
    <div className="flex flex-col gap-4">
      <Panel title="Migration Tickets" description="GitHub/Jira-style migration tickets ready for issue trackers.">
        <div className="flex items-center gap-2 mb-4">
          <button onClick={() => handleExport("json")} className="flex items-center gap-1.5 text-[12px] px-3 py-1.5 rounded" style={{ background: C.cardBg, border: `1px solid ${C.border}`, color: C.text }}>
            <Download size={13} /> Export JSON
          </button>
          <button onClick={() => handleExport("markdown")} className="flex items-center gap-1.5 text-[12px] px-3 py-1.5 rounded" style={{ background: C.cardBg, border: `1px solid ${C.border}`, color: C.text }}>
            <FileText size={13} /> Export Markdown
          </button>
        </div>

        <div className="flex flex-col gap-3">
          {list.map((t) => (
            <div key={t.ticket_id} className="p-3.5 rounded flex flex-col gap-2 text-[12px]" style={{ background: C.cardBg, border: `1px solid ${C.border}` }}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="font-mono font-bold" style={{ color: C.accent }}>{t.ticket_id}</span>
                  <span className="font-semibold" style={{ color: C.text }}>{t.title}</span>
                </div>
                <span className="px-2 py-0.5 rounded font-mono uppercase text-[10px]" style={{ background: C.bg, color: C.textMuted, border: `1px solid ${C.border}` }}>
                  {t.priority}
                </span>
              </div>
              <p style={{ color: C.textMuted }}>{t.description}</p>
              <div className="flex items-center gap-2 flex-wrap text-[11px]">
                {t.labels?.map((l) => (
                  <span key={l} className="px-1.5 py-0.5 rounded" style={{ background: C.bg, color: C.textFaint }}>#{l}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function CICDPage({ scan, apiBase }) {
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const base = normalizeApiBase(apiBase);
    fetch(`${base}/scans/${scan.scan_id}/cicd-policy`)
      .then((r) => r.json())
      .then((d) => {
        const list = Array.isArray(d) ? d : (Array.isArray(d?.results) ? d.results : []);
        setResults(list);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [scan.scan_id, apiBase]);

  if (loading) return <div className="p-8 text-center" style={{ color: C.textFaint }}><Loader2 className="animate-spin inline mr-2" size={16} /> Evaluating CI/CD gate policy…</div>;

  const list = Array.isArray(results) ? results : [];
  const blockedCount = list.filter((r) => r.action === "BLOCK").length;

  return (
    <div className="flex flex-col gap-4">
      <Panel title="CI/CD Security Gate Status" description="Policy rules evaluated against current scan findings.">
        <div className="p-4 rounded mb-4 flex items-center justify-between" style={{ background: blockedCount > 0 ? `${C.critical}15` : `${C.low}15`, border: `1px solid ${blockedCount > 0 ? C.critical : C.low}` }}>
          <div>
            <h4 className="text-[14px] font-bold" style={{ color: blockedCount > 0 ? C.critical : C.low }}>
              {blockedCount > 0 ? "❌ SECURITY GATE FAILED" : "✅ SECURITY GATE PASSED"}
            </h4>
            <p className="text-[12px]" style={{ color: C.textMuted }}>
              {blockedCount > 0 ? `${blockedCount} policy violation(s) would block a CI/CD pipeline build.` : "No BLOCK violations detected. Safe for deployment."}
            </p>
          </div>
        </div>

        <div className="flex flex-col gap-2">
          {list.map((r, i) => (
            <div key={i} className="p-3 rounded text-[12px] flex items-center justify-between" style={{ background: C.cardBg, border: `1px solid ${C.border}` }}>
              <div>
                <span className="font-semibold" style={{ color: C.text }}>{r.finding_title}</span>
                <p className="text-[11px]" style={{ color: C.textFaint }}>Rule: {r.policy_rule} · File: {r.file_path}</p>
              </div>
              <span className="px-2 py-0.5 rounded font-mono font-bold text-[11px]" style={{ background: r.action === "BLOCK" ? `${C.critical}20` : `${C.medium}20`, color: r.action === "BLOCK" ? C.critical : C.medium }}>
                {r.action}
              </span>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

/* -------------------------------------------------------------------------
   Simulation Floating Panel & Results Modal
------------------------------------------------------------------------- */
function SimulateFixPanel({ selectedCount, onRunSimulation, onClearSelection }) {
  if (selectedCount === 0) return null;
  return (
    <div
      className="fixed bottom-6 right-8 z-50 px-5 py-3.5 rounded-lg flex items-center gap-4 shadow-2xl transition-all animate-bounce-short"
      style={{
        background: C.panelRaised,
        border: `1.5px solid ${C.accent}`,
        boxShadow: "0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(76, 139, 245, 0.3)",
      }}
    >
      <div className="flex items-center gap-2">
        <div className="w-6 h-6 rounded-full flex items-center justify-center font-bold text-[12px]" style={{ background: C.accent, color: "#0C0E12", fontFamily: MONO }}>
          {selectedCount}
        </div>
        <span className="text-[13px] font-medium" style={{ color: C.text }}>
          finding{selectedCount !== 1 ? "s" : ""} selected for simulation
        </span>
      </div>
      <div className="flex items-center gap-2">
        <button
          onClick={onRunSimulation}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[12px] font-semibold transition-colors"
          style={{ background: C.accent, color: "#0C0E12" }}
        >
          <Sparkles size={14} />
          Simulate Fix
        </button>
        <button
          onClick={onClearSelection}
          className="px-2.5 py-1.5 rounded text-[11px] hover:underline"
          style={{ color: C.textMuted }}
        >
          Clear
        </button>
      </div>
    </div>
  );
}

function SimulateResultsModal({ scan, selectedFindingIds, onClose, apiBase }) {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    const base = normalizeApiBase(apiBase);
    fetch(`${base}/scans/${scan.scan_id}/simulate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding_ids: Array.from(selectedFindingIds) }),
    })
      .then((r) => {
        if (!r.ok) throw new Error("Simulation request failed");
        return r.json();
      })
      .then((d) => {
        if (!cancelled) {
          setResult(d);
          setLoading(false);
        }
      })
      .catch((e) => {
        if (!cancelled) {
          setError(e.message);
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [scan.scan_id, selectedFindingIds, apiBase]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: "rgba(12, 14, 18, 0.85)", backdropFilter: "blur(4px)" }}>
      <div
        className="w-full max-w-3xl rounded-xl overflow-hidden flex flex-col max-h-[90vh]"
        style={{ background: C.panel, border: `1px solid ${C.border}`, boxShadow: "0 25px 50px -12px rgba(0,0,0,0.8)" }}
      >
        {/* Modal Header */}
        <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: `1px solid ${C.border}`, background: C.panelRaised }}>
          <div className="flex items-center gap-2">
            <Sparkles size={18} color={C.accent} />
            <h3 className="text-[15px] font-bold" style={{ color: C.text, fontFamily: FONT }}>Crypto-Change Impact Simulator</h3>
          </div>
          <button onClick={onClose} aria-label="Close simulation modal" className="p-1 rounded hover:bg-white/10" style={{ color: C.textFaint }}>
            <X size={18} />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto flex-1 flex flex-col gap-5">
          {loading && (
            <div className="py-16 flex flex-col items-center justify-center gap-3" style={{ color: C.textMuted }}>
              <Loader2 size={24} className="animate-spin" color={C.accent} />
              <p className="text-[13px]">Re-computing risk scores and approximate blast radius…</p>
            </div>
          )}

          {error && (
            <div className="p-4 rounded flex items-center gap-2" style={{ background: "#2A1418", border: `1px solid ${C.critical}` }}>
              <AlertCircle size={16} color={C.critical} />
              <p className="text-[13px]" style={{ color: C.text }}>{error}</p>
            </div>
          )}

          {result && (
            <>
              {/* Summary Statement Line */}
              <div className="p-4 rounded-lg flex items-start gap-3" style={{ background: C.accentDim, border: `1px solid ${C.accent}55` }}>
                <Sparkles size={18} color={C.accent} className="shrink-0 mt-0.5" />
                <div>
                  <p className="text-[14px] font-semibold leading-relaxed" style={{ color: C.text }}>
                    {result.summary_statement}
                  </p>
                  <p className="text-[11px] mt-1" style={{ color: C.textMuted }}>
                    Re-ran <code style={{ fontFamily: MONO, color: C.accent }}>compute_scores()</code> assuming {result.resolved_finding_ids.length} selected finding{result.resolved_finding_ids.length !== 1 ? "s" : ""} were resolved.
                  </p>
                </div>
              </div>

              {/* Grade & Score Comparison */}
              <div className="grid grid-cols-12 gap-3">
                {/* Grade shift card */}
                <div className="col-span-4 p-4 rounded-lg flex flex-col items-center justify-center" style={{ background: C.panelRaised, border: `1px solid ${C.border}` }}>
                  <span className="text-[11px] uppercase tracking-wider mb-2" style={{ color: C.textFaint }}>Grade Impact</span>
                  <div className="flex items-center gap-3 font-mono font-bold text-[24px]">
                    <span style={{ color: C.critical }}>{result.grade_change.from}</span>
                    <ChevronRight size={20} color={C.textFaint} />
                    <span style={{ color: C.low }}>{result.grade_change.to}</span>
                  </div>
                </div>

                {/* Score metrics comparison */}
                <div className="col-span-8 p-4 rounded-lg grid grid-cols-2 gap-3" style={{ background: C.panelRaised, border: `1px solid ${C.border}` }}>
                  {Object.entries(result.metric_deltas).map(([metric, d]) => {
                    const label = metric.replace(/_/g, " ").replace("score", "");
                    return (
                      <div key={metric} className="p-2.5 rounded flex flex-col" style={{ background: C.bg, border: `1px solid ${C.border}` }}>
                        <span className="text-[10.5px] uppercase font-semibold truncate" style={{ color: C.textFaint }}>{label}</span>
                        <div className="flex items-baseline justify-between mt-1">
                          <span className="text-[15px] font-bold" style={{ color: C.text, fontFamily: MONO }}>
                            {d.original} <span style={{ color: C.textFaint, fontSize: 12 }}>→</span> <span style={{ color: C.low }}>{d.simulated}</span>
                          </span>
                          <span className="text-[11px] font-mono font-semibold px-1.5 py-0.5 rounded" style={{ background: `${C.low}20`, color: C.low }}>
                            +{d.delta.toFixed(1)}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Part 2: Related Findings & Heuristic Blast Radius */}
              <div className="flex flex-col gap-3">
                <h4 className="text-[13px] font-semibold uppercase tracking-wider" style={{ color: C.text, fontFamily: FONT }}>
                  Simulated Fixes & Related Assets (Approximate Blast Radius)
                </h4>

                {/* Mandatory Disclaimer */}
                <div className="p-3 rounded flex items-start gap-2 text-[11.5px] leading-relaxed" style={{ background: C.panelRaised, border: `1px solid ${C.high}55`, color: C.high }}>
                  <AlertCircle size={15} className="shrink-0 mt-0.5" />
                  <span>{result.disclaimer}</span>
                </div>

                <div className="flex flex-col gap-3 mt-1">
                  {result.resolved_finding_ids.map((fid) => {
                    const finding = scan.findings.find((f) => f.id === fid);
                    const related = result.related_findings[fid] || [];
                    return (
                      <div key={fid} className="p-3.5 rounded-lg flex flex-col gap-2" style={{ background: C.panelRaised, border: `1px solid ${C.border}` }}>
                        <div className="flex items-center justify-between">
                          <span className="text-[13px] font-medium" style={{ color: C.text }}>{finding?.title || fid}</span>
                          <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded font-bold" style={{ background: `${C.accent}20`, color: C.accent }}>
                            Simulated Resolved
                          </span>
                        </div>
                        <p className="text-[11px] font-mono" style={{ color: C.textFaint }}>{finding?.file_path}</p>

                        {/* Related findings list */}
                        {related.length > 0 ? (
                          <div className="mt-2 pl-3 border-l-2 flex flex-col gap-2" style={{ borderColor: C.accent }}>
                            <p className="text-[11px] font-semibold" style={{ color: C.textMuted }}>
                              {related.length} Related Finding{related.length !== 1 ? "s" : ""} on same asset / pattern:
                            </p>
                            {related.map((rf) => (
                              <div key={rf.id} className="p-2 rounded text-[11.5px] flex flex-col gap-1" style={{ background: C.bg, border: `1px solid ${C.border}` }}>
                                <div className="flex items-center justify-between">
                                  <span className="font-medium" style={{ color: C.text }}>{rf.title}</span>
                                  <span className="text-[9.5px] font-mono uppercase" style={{ color: SEVERITY_COLOR[rf.severity] }}>{rf.severity}</span>
                                </div>
                                <div className="flex items-center gap-1.5 flex-wrap">
                                  {rf.relationship_reasons.map((reason, i) => (
                                    <span key={i} className="text-[9.5px] px-1.5 py-0.5 rounded font-mono" style={{ background: C.accentDim, color: C.accent }}>
                                      {reason}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p className="text-[11px] italic mt-1" style={{ color: C.textFaint }}>
                            No other findings in this scan share the same file, directory, algorithm, or certificate subject.
                          </p>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------
   App shell
------------------------------------------------------------------------- */
export default function QuantumShieldDashboard() {
  const [apiBase, setApiBase] = useState(DEFAULT_API_BASE);
  const [scan, setScan] = useState(null);
  const [history, setHistory] = useState([]);
  const [page, setPage] = useState("overview");

  // Crypto-Change Impact Simulator Selection State
  const [selectedForSimulation, setSelectedForSimulation] = useState(new Set());
  const [showSimulateModal, setShowSimulateModal] = useState(false);

  const findings = useMemo(() => (scan ? scan.findings.map(normalizeFinding) : []), [scan]);

  const toggleSimulate = useCallback((id) => {
    setSelectedForSimulation((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }, []);

  const refreshHistory = useCallback(() => {
    const base = normalizeApiBase(apiBase);
    fetch(`${base}/scans`)
      .then((r) => r.json())
      .then((d) => {
        if (Array.isArray(d)) setHistory(d);
      })
      .catch(() => { });
  }, [apiBase]);

  function handleScanComplete(data) {
    setScan(data);
    setSelectedForSimulation(new Set());
    setShowSimulateModal(false);
    setPage("overview");
    refreshHistory();
  }

  if (!scan) {
    return (
      <ErrorBoundary>
        <UploadScreen apiBase={apiBase} setApiBase={setApiBase} onScanComplete={handleScanComplete} />
      </ErrorBoundary>
    );
  }

  const PAGES = {
    overview: <OverviewPage scan={scan} history={history} findings={findings} />,
    findings: (
      <FindingsPage
        findings={findings}
        selectedForSimulation={selectedForSimulation}
        onToggleSimulate={toggleSimulate}
      />
    ),
    inventory: (
      <InventoryPage
        scan={scan}
        findings={findings}
        apiBase={apiBase}
        selectedForSimulation={selectedForSimulation}
        onToggleSimulate={toggleSimulate}
      />
    ),
    quantum: <QuantumPage scan={scan} findings={findings} apiBase={apiBase} />,
    reports: <ReportsPage scan={scan} apiBase={apiBase} />,
    copilot: <CopilotPage scan={scan} apiBase={apiBase} />,
    graph: <DependencyGraphPage scan={scan} apiBase={apiBase} />,
    agility: <AgilityPage scan={scan} apiBase={apiBase} />,
    blast: <BlastRadiusPage scan={scan} apiBase={apiBase} />,
    validation: <ValidationPage scan={scan} apiBase={apiBase} />,
    remediation: <RemediationPage scan={scan} apiBase={apiBase} />,
    tickets: <TicketsPage scan={scan} apiBase={apiBase} />,
    cicd: <CICDPage scan={scan} apiBase={apiBase} />,
  };

  return (
    <ErrorBoundary>
      <div className="relative min-h-screen w-full flex" style={{ background: "transparent", fontFamily: FONT }}>
        <BackgroundVideo src="/bg-video.mp4" overlayOpacity={0.75} />
        <aside className="w-56 shrink-0 flex flex-col py-4 relative z-10" style={{ borderRight: `1px solid ${C.border}`, background: C.bg }}>
          <div className="flex items-center gap-2 px-4 mb-6">
            <div className="w-7 h-7 rounded flex items-center justify-center shrink-0" style={{ background: C.accent }}>
              <ShieldCheck size={16} color="#0C0E12" strokeWidth={2.5} />
            </div>
            <div>
              <p className="text-[13px] font-semibold leading-tight" style={{ color: C.text }}>QuantumShield</p>
              <p className="text-[10px] leading-tight" style={{ color: C.textFaint }}>Security scanner</p>
            </div>
          </div>
          <nav className="flex flex-col gap-0.5 px-2">
            {NAV_ITEMS.map((item) => {
              const active = page === item.key;
              return (
                <button key={item.key} onClick={() => setPage(item.key)} className="flex items-center gap-2.5 px-3 py-2 rounded text-[13px] text-left"
                  style={{ background: active ? C.accentDim : "transparent", color: active ? C.accent : C.textMuted }}>
                  <item.icon size={15} />
                  {item.label}
                </button>
              );
            })}
          </nav>
          <div className="mt-auto px-4 pt-4" style={{ borderTop: `1px solid ${C.border}` }}>
            <p className="text-[10px] leading-snug" style={{ color: C.textFaint }}>
              Static analysis only — pair with a full audit for compliance sign-off.
            </p>
          </div>
        </aside>

        <div className="flex-1 flex flex-col min-w-0 relative z-10">
          <div className="flex items-center justify-between px-6 py-3.5" style={{ borderBottom: `1px solid ${C.border}` }}>
            <div className="flex items-center gap-2">
              <span className="text-[13px]" style={{ color: C.text, fontFamily: MONO }}>{scan.target_name}</span>
              <span className="text-[11px] ml-2" style={{ color: C.textFaint }}>
                scanned {new Date(scan.completed_at).toLocaleString()}
              </span>
            </div>
            <button onClick={() => setScan(null)} className="flex items-center gap-2 text-[12px] px-3 py-1.5 rounded" style={{ background: C.accent, color: "#0C0E12", fontWeight: 500 }}>
              <RefreshCw size={13} />
              Run new scan
            </button>
          </div>
          <div className="px-6 py-4">{PAGES[page]}</div>
        </div>

        {/* Persistent Simulate Fix Floating Panel */}
        <SimulateFixPanel
          selectedCount={selectedForSimulation.size}
          onRunSimulation={() => setShowSimulateModal(true)}
          onClearSelection={() => setSelectedForSimulation(new Set())}
        />

        {/* Crypto-Change Impact Simulation Modal */}
        {showSimulateModal && (
          <SimulateResultsModal
            scan={scan}
            selectedFindingIds={selectedForSimulation}
            onClose={() => setShowSimulateModal(false)}
            apiBase={apiBase}
          />
        )}
      </div>
    </ErrorBoundary>
  );
}


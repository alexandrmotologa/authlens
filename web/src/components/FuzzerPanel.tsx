import React, { useState, useEffect } from 'react';
import { AttackVector, SuiteReport } from '../types';
import { Bug, AlertTriangle, ShieldCheck, ShieldAlert, Play, Copy, Check, ExternalLink, Terminal, Shield } from 'lucide-react';

interface FuzzerPanelProps {
  onInspectToken: (token: string) => void;
}

export const FuzzerPanel: React.FC<FuzzerPanelProps> = ({ onInspectToken }) => {
  const [vectors, setVectors] = useState<AttackVector[]>([]);
  const [targetUrl, setTargetUrl] = useState<string>('http://localhost:8080/api/protected');
  const [method, setMethod] = useState<string>('GET');
  const [headerFormat, setHeaderFormat] = useState<string>('Authorization: Bearer {{token}}');
  const [running, setRunning] = useState<boolean>(false);
  const [report, setReport] = useState<SuiteReport | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  useEffect(() => {
    fetchVectors();
  }, []);

  const fetchVectors = async () => {
    try {
      const res = await fetch('/api/fuzzer/vectors');
      if (res.ok) {
        const data = await res.json();
        setVectors(data);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleRunAudit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl.trim()) return;

    setRunning(true);
    try {
      const res = await fetch('/api/fuzzer/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_url: targetUrl,
          method,
          header_format: headerFormat,
          persona_id: 'admin',
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setReport(data);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setRunning(false);
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header and overview */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-white tracking-tight">Middleware Security Fuzzer &amp; Attack Lab</h2>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-rose-950 text-rose-400 border border-rose-800">
              9 Attack Vectors
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Probe your backend authentication middleware against algorithm confusion, key forgery, and timestamp bypasses
          </p>
        </div>
      </div>

      {/* Active Probe Form */}
      <div className="rounded-xl border border-slate-800 bg-[#0B0F19] p-5 space-y-4">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-white">Live Backend Security Auditor</h3>
        </div>

        <form onSubmit={handleRunAudit} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div className="md:col-span-1">
              <label className="block text-xs font-medium text-slate-300 mb-1">HTTP Method</label>
              <select
                value={method}
                onChange={(e) => setMethod(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-400 focus:outline-none focus:border-cyan-500"
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
              </select>
            </div>

            <div className="md:col-span-3">
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs font-medium text-slate-300">
                  Target Backend Protected Endpoint URL
                </label>
                <button
                  type="button"
                  onClick={() => setTargetUrl('http://127.0.0.1:9099/api/mock/protected')}
                  className="text-[11px] text-cyan-400 hover:text-cyan-300 underline font-mono cursor-pointer"
                >
                  Quick Target: Internal Mock Sandbox (Port 9099)
                </button>
              </div>
              <input
                type="url"
                required
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="http://localhost:8080/api/users/me"
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Header Template (use <code className="text-cyan-400 font-mono">{'{{token}}'}</code> placeholder)
            </label>
            <input
              type="text"
              value={headerFormat}
              onChange={(e) => setHeaderFormat(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex items-center justify-between pt-1">
            <p className="text-xs text-slate-500">
              AuthLens will fire all 9 compromised vectors sequentially and verify that your middleware returns HTTP 401 or 403.
            </p>

            <button
              type="submit"
              disabled={running}
              className="inline-flex items-center gap-2 px-5 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-medium text-xs shadow-lg shadow-rose-600/20 transition disabled:opacity-50"
            >
              <Play className={`w-3.5 h-3.5 fill-current ${running ? 'animate-pulse' : ''}`} />
              <span>{running ? 'Running Security Audit...' : 'Run Security Audit'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Audit Report Scorecard */}
      {report && (
        <div className="rounded-xl border border-slate-800 bg-[#0B0F19] overflow-hidden space-y-4 p-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
            <div>
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white">Security Audit Results</h3>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Target: {report.target_url} &bull; {new Date(report.timestamp).toLocaleTimeString()}
              </p>
            </div>

            <div className="flex items-center gap-4">
              <div className="text-right">
                <span className="text-[11px] text-slate-400 block">Security Score:</span>
                <span
                  className={`text-2xl font-bold font-mono ${
                    report.score_pct === 100
                      ? 'text-emerald-400'
                      : report.score_pct >= 80
                      ? 'text-amber-400'
                      : 'text-rose-400'
                  }`}
                >
                  {report.score_pct.toFixed(1)}%
                </span>
              </div>
            </div>
          </div>

          {/* Metric Pills */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/80">
              <span className="text-[10px] text-slate-400 uppercase font-bold block">Total Tests</span>
              <span className="text-lg font-bold font-mono text-white">{report.total_tests}</span>
            </div>
            <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-800/60">
              <span className="text-[10px] text-emerald-400 uppercase font-bold block">Secure (401/403)</span>
              <span className="text-lg font-bold font-mono text-emerald-400">{report.passed}</span>
            </div>
            <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800/60">
              <span className="text-[10px] text-rose-400 uppercase font-bold block">Vulnerable (2xx)</span>
              <span className="text-lg font-bold font-mono text-rose-400">{report.failed}</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/80">
              <span className="text-[10px] text-slate-400 uppercase font-bold block">Network Errors</span>
              <span className="text-lg font-bold font-mono text-slate-300">{report.errors}</span>
            </div>
          </div>

          {/* Results Table */}
          <div className="border border-slate-800 rounded-lg overflow-hidden divide-y divide-slate-800/80">
            {report.results.map((r) => {
              const isSecure = r.verdict === 'SECURE';
              const isVuln = r.verdict === 'VULNERABLE';

              return (
                <div key={r.vector_id} className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-white">{r.vector_name}</span>
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300">
                        {r.category}
                      </span>
                    </div>
                    {r.error_message && (
                      <p className="text-rose-400 text-[11px] font-mono">{r.error_message}</p>
                    )}
                  </div>

                  <div className="flex items-center gap-3 font-mono">
                    <span className="text-slate-400">{r.duration_ms}ms</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                        isSecure
                          ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                          : isVuln
                          ? 'bg-rose-950 text-rose-400 border border-rose-800 animate-pulse'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {r.status_code ? `HTTP ${r.status_code}` : r.verdict}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase ${
                        isSecure
                          ? 'text-emerald-400'
                          : isVuln
                          ? 'text-rose-400 font-extrabold'
                          : 'text-amber-400'
                      }`}
                    >
                      {r.verdict}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Vectors Catalog */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold text-white">Compromised Token Vectors Catalog</h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {vectors.map((v) => (
            <div
              key={v.id}
              className="rounded-xl border border-slate-800 bg-[#0B0F19] p-4 space-y-3 hover:border-slate-700 transition"
            >
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="flex items-center gap-2">
                    <h4 className="text-xs font-bold text-white">{v.name}</h4>
                    <span
                      className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-bold ${
                        v.severity === 'Critical'
                          ? 'bg-rose-950 text-rose-400 border border-rose-800'
                          : v.severity === 'High'
                          ? 'bg-amber-950 text-amber-400 border border-amber-800'
                          : 'bg-yellow-950 text-yellow-400 border border-yellow-800'
                      }`}
                    >
                      {v.severity}
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-500">{v.category}</span>
                </div>

                <div className="flex items-center space-x-1">
                  <button
                    onClick={() => copyToClipboard(v.token, v.id)}
                    title="Copy Adversarial Token"
                    className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition"
                  >
                    {copiedKey === v.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                  <button
                    onClick={() => onInspectToken(v.token)}
                    title="Inspect in JWT Studio"
                    className="p-1.5 rounded-lg bg-indigo-950/80 hover:bg-indigo-900 border border-indigo-700 text-indigo-300 text-xs transition"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              <p className="text-xs text-slate-400 leading-relaxed">{v.description}</p>

              <div className="pt-2 border-t border-slate-800/80 text-[11px]">
                <span className="text-cyan-400 font-semibold block mb-0.5">Remediation:</span>
                <span className="text-slate-400">{v.remediation}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

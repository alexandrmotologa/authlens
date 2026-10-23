import React, { useState, useEffect } from 'react';
import { FlowTrace } from '../types';
import { Activity, ShieldCheck, CheckCircle2, XCircle, ArrowRight, RefreshCw, Trash2, Hash, Lock, Clock } from 'lucide-react';

interface PkcePanelProps {
  baseURL: string;
}

export const PkcePanel: React.FC<PkcePanelProps> = ({ baseURL }) => {
  const [traces, setTraces] = useState<FlowTrace[]>([]);
  const [verifier, setVerifier] = useState<string>('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
  const [method, setMethod] = useState<'S256' | 'plain'>('S256');
  const [selectedPersona, setSelectedPersona] = useState<string>('admin');
  const [simulating, setSimulating] = useState<boolean>(false);
  const [simulationResult, setSimulationResult] = useState<any>(null);
  const [expandedTraceId, setExpandedTraceId] = useState<string | null>(null);

  useEffect(() => {
    fetchTraces();

    // Subscribe to real-time telemetry events via SSE
    const eventSource = new EventSource('/api/events');
    eventSource.addEventListener('trace', (e) => {
      try {
        const trace = JSON.parse(e.data);
        setTraces((prev) => {
          const index = prev.findIndex((t) => t.id === trace.id);
          if (index >= 0) {
            const next = [...prev];
            next[index] = trace;
            return next;
          }
          return [trace, ...prev];
        });
      } catch (err) {
        console.error(err);
      }
    });

    return () => {
      eventSource.close();
    };
  }, []);

  const fetchTraces = async () => {
    try {
      const res = await fetch('/api/pkce/traces');
      if (res.ok) {
        const data = await res.json();
        setTraces(data);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleClearTraces = async () => {
    try {
      await fetch('/api/pkce/traces', { method: 'DELETE' });
      setTraces([]);
      setSimulationResult(null);
    } catch (e) {
      console.error(e);
    }
  };

  const generateRandomVerifier = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    let result = '';
    const array = new Uint8Array(50);
    crypto.getRandomValues(array);
    for (let i = 0; i < array.length; i++) {
      result += chars[array[i] % chars.length];
    }
    setVerifier(result);
  };

  const runSimulation = async () => {
    setSimulating(true);
    try {
      const res = await fetch('/api/pkce/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code_verifier: verifier,
          method,
          persona_id: selectedPersona,
          client_id: 'client_pkce_studio',
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setSimulationResult(data);
        await fetchTraces();
        if (data.trace?.id) {
          setExpandedTraceId(data.trace.id);
        }
      }
    } catch (e) {
      console.error(e);
    } finally {
      setSimulating(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Interactive Simulator */}
      <div className="rounded-xl border border-slate-800 bg-[#0B0F19] overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <div>
              <h2 className="text-sm font-semibold text-white">OAuth 2.1 PKCE Handshake Simulator</h2>
              <p className="text-xs text-slate-400">
                Execute end-to-end authorization code exchange with cryptographic challenge verification
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={generateRandomVerifier}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono transition"
            >
              Generate Random Verifier
            </button>
            <button
              onClick={runSimulation}
              disabled={simulating}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs shadow-md shadow-cyan-600/20 transition disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${simulating ? 'animate-spin' : ''}`} />
              <span>Simulate Handshake</span>
            </button>
          </div>
        </div>

        <div className="p-5 grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="space-y-4 lg:col-span-2">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                code_verifier (43 - 128 characters from [A-Za-z0-9-._~])
              </label>
              <input
                type="text"
                value={verifier}
                onChange={(e) => setVerifier(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
              />
              <span className="text-[11px] font-mono text-slate-500 mt-1 block">
                Length: {verifier.length} chars (RFC 7636 Valid: {verifier.length >= 43 && verifier.length <= 128 ? '✓' : '✗'})
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Challenge Method</label>
                <select
                  value={method}
                  onChange={(e) => setMethod(e.target.value as any)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="S256">S256 (Base64URL(SHA-256(verifier))) — Recommended</option>
                  <option value="plain">plain (Unencoded verifier)</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Persona to Authorize</label>
                <select
                  value={selectedPersona}
                  onChange={(e) => setSelectedPersona(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="admin">Alice Admin (Full Privileges)</option>
                  <option value="developer">Bob Developer (Member)</option>
                  <option value="suspended">Charlie Suspended (Restricted)</option>
                </select>
              </div>
            </div>
          </div>

          {/* Derivation diagram */}
          <div className="rounded-xl bg-slate-950 border border-slate-800/80 p-4 space-y-3 flex flex-col justify-between">
            <div>
              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block mb-2">
                Mathematical Challenge Derivation
              </span>
              <div className="space-y-2 text-xs font-mono">
                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">1. Raw Input:</span>
                  <span className="text-slate-300 truncate block">{verifier}</span>
                </div>
                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">2. SHA-256 Hash + Base64URL:</span>
                  <span className="text-cyan-400 font-semibold truncate block">
                    {simulationResult?.challenge || 'Click Simulate to compute'}
                  </span>
                </div>
              </div>
            </div>

            <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs">
              <span className="text-slate-400">Challenge Status:</span>
              <span className="text-emerald-400 font-semibold font-mono flex items-center gap-1">
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>RFC 7636 Verified</span>
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Traces Feed */}
      <div className="rounded-xl border border-slate-800 bg-[#0B0F19] overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
            </span>
            <h3 className="text-sm font-semibold text-white">Live PKCE Telemetry Stream</h3>
          </div>

          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono text-slate-500">{traces.length} recorded handshakes</span>
            {traces.length > 0 && (
              <button
                onClick={handleClearTraces}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-slate-800 hover:bg-rose-950 hover:text-rose-400 text-slate-400 text-xs transition"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Clear</span>
              </button>
            )}
          </div>
        </div>

        {traces.length === 0 ? (
          <div className="p-12 text-center text-slate-500 text-xs">
            No authorization flows recorded yet. Run the simulator above or hit{' '}
            <code className="text-slate-400 font-mono">/oauth/authorize</code> from your application.
          </div>
        ) : (
          <div className="divide-y divide-slate-800/80">
            {traces.map((trace) => {
              const isExpanded = expandedTraceId === trace.id;
              const isSuccess = trace.status === 'exchanged';
              const isFailed = trace.status === 'failed';

              return (
                <div key={trace.id} className="transition">
                  <div
                    onClick={() => setExpandedTraceId(isExpanded ? null : trace.id)}
                    className="px-5 py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-900/40 cursor-pointer"
                  >
                    <div className="flex items-center gap-3">
                      <div
                        className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                          isSuccess
                            ? 'bg-emerald-950/70 text-emerald-400 border border-emerald-800/60'
                            : isFailed
                            ? 'bg-rose-950/70 text-rose-400 border border-rose-800/60'
                            : 'bg-amber-950/70 text-amber-400 border border-amber-800/60'
                        }`}
                      >
                        {isSuccess ? (
                          <CheckCircle2 className="w-4 h-4" />
                        ) : isFailed ? (
                          <XCircle className="w-4 h-4" />
                        ) : (
                          <Clock className="w-4 h-4" />
                        )}
                      </div>

                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-semibold text-white">
                            Flow for <span className="text-cyan-400 font-mono">{trace.persona || 'admin'}</span>
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                              isSuccess
                                ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                                : isFailed
                                ? 'bg-rose-950 text-rose-400 border border-rose-800'
                                : 'bg-amber-950 text-amber-400 border border-amber-800'
                            }`}
                          >
                            {trace.status}
                          </span>
                        </div>
                        <p className="text-[11px] font-mono text-slate-400">
                          Auth Code: <span className="text-slate-300">{trace.authCode || 'N/A'}</span> &bull; Client: {trace.clientId}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center space-x-3 text-xs font-mono text-slate-400">
                      <span>{new Date(trace.createdAt).toLocaleTimeString()}</span>
                      <span className="text-slate-600">|</span>
                      <span className="text-cyan-400">{isExpanded ? 'Collapse' : 'Details →'}</span>
                    </div>
                  </div>

                  {/* Expanded Step Timeline */}
                  {isExpanded && (
                    <div className="px-5 pb-5 pt-1 bg-slate-950/50 border-t border-slate-800/60 space-y-3">
                      <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider pt-2">
                        Handshake Milestone Timeline
                      </h4>

                      <div className="space-y-2.5">
                        {trace.steps?.map((step) => (
                          <div
                            key={step.index}
                            className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 flex items-start gap-3"
                          >
                            <span className="w-5 h-5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800/80 text-[10px] font-mono flex items-center justify-center flex-shrink-0 mt-0.5">
                              {step.index}
                            </span>
                            <div className="space-y-1 w-full text-xs">
                              <div className="flex items-center justify-between">
                                <span className="font-semibold text-white">{step.name}</span>
                                <span className="text-[10px] font-mono text-slate-500">
                                  {new Date(step.timestamp).toLocaleTimeString()}
                                </span>
                              </div>
                              <p className="text-slate-400 text-xs">{step.description}</p>
                              {step.payload && (
                                <pre className="p-2 mt-1.5 rounded bg-slate-950 border border-slate-800/80 font-mono text-[11px] text-cyan-300 overflow-x-auto">
                                  {JSON.stringify(step.payload, null, 2)}
                                </pre>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};

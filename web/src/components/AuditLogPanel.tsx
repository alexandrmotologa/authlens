import React, { useState, useEffect, useMemo } from 'react';
import { AuditLogEntry } from '../types';
import {
  ListFilter,
  Trash2,
  RefreshCw,
  Search,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  Radio,
  Pause,
  Play,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  Globe
} from 'lucide-react';

export const AuditLogPanel: React.FC = () => {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [isLive, setIsLive] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<'all' | '2xx' | '3xx' | '4xx' | '5xx'>('all');
  const [methodFilter, setMethodFilter] = useState<string>('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const fetchLogs = async () => {
    try {
      const res = await fetch('/api/logs');
      if (res.ok) {
        const data: AuditLogEntry[] = await res.json();
        setLogs(data);
      }
    } catch (e) {
      console.error('Failed to load audit logs:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();

    if (!isLive) return;

    const eventSource = new EventSource('/api/events');
    eventSource.addEventListener('audit_log', (e: MessageEvent) => {
      try {
        const entry: AuditLogEntry = JSON.parse(e.data);
        setLogs((prev) => [entry, ...prev.slice(0, 299)]);
      } catch (err) {
        console.error('Failed to parse incoming audit log SSE:', err);
      }
    });

    return () => {
      eventSource.close();
    };
  }, [isLive]);

  const handleClearLogs = async () => {
    try {
      const res = await fetch('/api/logs/clear', { method: 'POST' });
      if (res.ok) {
        setLogs([]);
      }
    } catch (e) {
      console.error('Failed to clear audit logs:', e);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      // Search filter
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchesQuery =
          log.path.toLowerCase().includes(query) ||
          log.client_ip.toLowerCase().includes(query) ||
          log.user_agent.toLowerCase().includes(query) ||
          log.method.toLowerCase().includes(query);
        if (!matchesQuery) return false;
      }

      // Status filter
      if (statusFilter !== 'all') {
        const code = log.status_code;
        if (statusFilter === '2xx' && (code < 200 || code >= 300)) return false;
        if (statusFilter === '3xx' && (code < 300 || code >= 400)) return false;
        if (statusFilter === '4xx' && (code < 400 || code >= 500)) return false;
        if (statusFilter === '5xx' && code < 500) return false;
      }

      // Method filter
      if (methodFilter !== 'all') {
        if (log.method.toUpperCase() !== methodFilter) return false;
      }

      return true;
    });
  }, [logs, searchQuery, statusFilter, methodFilter]);

  // Statistics calculation
  const stats = useMemo(() => {
    const total = logs.length;
    let s2xx = 0;
    let s3xx = 0;
    let s4xx = 0;
    let s5xx = 0;

    logs.forEach((l) => {
      if (l.status_code >= 200 && l.status_code < 300) s2xx++;
      else if (l.status_code >= 300 && l.status_code < 400) s3xx++;
      else if (l.status_code >= 400 && l.status_code < 500) s4xx++;
      else if (l.status_code >= 500) s5xx++;
    });

    const successRate = total > 0 ? Math.round(((s2xx + s3xx) / total) * 100) : 100;
    return { total, s2xx, s3xx, s4xx, s5xx, successRate };
  }, [logs]);

  const getMethodBadgeClass = (m: string) => {
    switch (m.toUpperCase()) {
      case 'GET':
        return 'bg-sky-500/10 text-sky-400 border-sky-500/30';
      case 'POST':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'PUT':
        return 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30';
      case 'DELETE':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      default:
        return 'bg-slate-500/10 text-slate-400 border-slate-500/30';
    }
  };

  const getStatusBadgeClass = (status: number) => {
    if (status >= 200 && status < 300) {
      return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    }
    if (status >= 300 && status < 400) {
      return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
    }
    if (status >= 400 && status < 500) {
      return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    }
    return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
  };

  const formatTimestamp = (iso: string) => {
    try {
      const date = new Date(iso);
      return date.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) +
        '.' +
        String(date.getMilliseconds()).padStart(3, '0');
    } catch {
      return iso;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-white tracking-tight">Live HTTP Traffic &amp; Request Audit Log</h2>
            <div className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono border bg-slate-900 border-slate-800">
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  isLive ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'
                }`}
              />
              <span className={isLive ? 'text-emerald-400' : 'text-amber-400'}>
                {isLive ? 'LIVE SSE' : 'PAUSED'}
              </span>
            </div>
          </div>
          <p className="text-xs text-slate-400">
            Real-time telemetry capturing all incoming requests, OIDC handshakes, JWKS queries, and fuzzer probes
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsLive(!isLive)}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition ${
              isLive
                ? 'bg-slate-900 text-slate-300 border-slate-700 hover:bg-slate-800'
                : 'bg-emerald-950/60 text-emerald-400 border-emerald-800 hover:bg-emerald-900/60'
            }`}
          >
            {isLive ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            <span>{isLive ? 'Pause Stream' : 'Resume Stream'}</span>
          </button>

          <button
            onClick={fetchLogs}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 text-slate-300 border border-slate-700 hover:bg-slate-800 text-xs font-medium transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>

          <button
            onClick={handleClearLogs}
            disabled={logs.length === 0}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-950/50 text-rose-400 border border-rose-900/60 hover:bg-rose-900/60 text-xs font-medium transition disabled:opacity-40"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear Logs</span>
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="rounded-xl border border-slate-800 bg-[#0B0F19] p-4">
          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-1">Total Requests</div>
          <div className="text-2xl font-bold font-mono text-white">{stats.total}</div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#0B0F19] p-4">
          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-1">Success Rate</div>
          <div className="text-2xl font-bold font-mono text-emerald-400">{stats.successRate}%</div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#0B0F19] p-4">
          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-1">Client Errors (4xx)</div>
          <div className="text-2xl font-bold font-mono text-amber-400">{stats.s4xx}</div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#0B0F19] p-4">
          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-1">Server Errors (5xx)</div>
          <div className="text-2xl font-bold font-mono text-rose-400">{stats.s5xx}</div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="rounded-xl border border-slate-800 bg-[#0B0F19] p-3 flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter by path, client IP, or user agent..."
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Method Select */}
          <div className="flex items-center gap-1 bg-slate-950 border border-slate-800 rounded-lg p-0.5">
            {['all', 'GET', 'POST', 'PUT', 'DELETE'].map((m) => (
              <button
                key={m}
                onClick={() => setMethodFilter(m)}
                className={`px-2 py-1 rounded text-[11px] font-mono transition ${
                  methodFilter === m
                    ? 'bg-cyan-500/20 text-cyan-300 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {m.toUpperCase()}
              </button>
            ))}
          </div>

          {/* Status Filter */}
          <div className="flex items-center gap-1 bg-slate-950 border border-slate-800 rounded-lg p-0.5">
            {[
              { id: 'all', label: 'All' },
              { id: '2xx', label: '2xx' },
              { id: '3xx', label: '3xx' },
              { id: '4xx', label: '4xx' },
              { id: '5xx', label: '5xx' },
            ].map((s) => (
              <button
                key={s.id}
                onClick={() => setStatusFilter(s.id as any)}
                className={`px-2 py-1 rounded text-[11px] font-mono transition ${
                  statusFilter === s.id
                    ? 'bg-cyan-500/20 text-cyan-300 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Logs Table */}
      <div className="rounded-xl border border-slate-800 bg-[#0B0F19] overflow-hidden">
        {filteredLogs.length === 0 ? (
          <div className="p-12 text-center space-y-3">
            <Radio className="w-8 h-8 text-slate-600 mx-auto" />
            <h4 className="text-sm font-semibold text-slate-300">No requests recorded yet</h4>
            <p className="text-xs text-slate-500 max-w-md mx-auto">
              Any HTTP request made to port 9099 (discovery, JWKS, token exchanges, or mock sandbox calls) will stream here in real time.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400 uppercase text-[10px] tracking-wider">
                <tr>
                  <th className="py-2.5 px-3 w-8"></th>
                  <th className="py-2.5 px-3 w-28">Timestamp</th>
                  <th className="py-2.5 px-3 w-20">Method</th>
                  <th className="py-2.5 px-3 w-20">Status</th>
                  <th className="py-2.5 px-3">Path</th>
                  <th className="py-2.5 px-3 w-24">Latency</th>
                  <th className="py-2.5 px-3 w-32">Client IP</th>
                  <th className="py-2.5 px-3 w-16 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredLogs.map((log) => {
                  const isExpanded = expandedId === log.id;
                  return (
                    <React.Fragment key={log.id}>
                      <tr
                        onClick={() => setExpandedId(isExpanded ? null : log.id)}
                        className={`hover:bg-slate-900/60 cursor-pointer transition ${
                          isExpanded ? 'bg-slate-900/40' : ''
                        }`}
                      >
                        <td className="py-2.5 px-3 text-slate-500">
                          {isExpanded ? (
                            <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
                          ) : (
                            <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
                          )}
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap text-[11px]">
                          {formatTimestamp(log.timestamp)}
                        </td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getMethodBadgeClass(
                              log.method
                            )}`}
                          >
                            {log.method}
                          </span>
                        </td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getStatusBadgeClass(
                              log.status_code
                            )}`}
                          >
                            {log.status_code}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-200 font-medium truncate max-w-md">
                          {log.path}
                          {log.query ? <span className="text-slate-400 font-normal">?{log.query}</span> : null}
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap text-[11px]">
                          {log.latency_ms} ms
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap text-[11px]">
                          {log.client_ip}
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              copyToClipboard(JSON.stringify(log, null, 2), log.id);
                            }}
                            className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition"
                            title="Copy raw JSON log entry"
                          >
                            {copiedId === log.id ? (
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </td>
                      </tr>

                      {isExpanded && (
                        <tr className="bg-slate-950/80 border-b border-slate-800">
                          <td colSpan={8} className="p-4 space-y-2 text-xs">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                              <div className="space-y-1">
                                <div className="text-[10px] uppercase text-slate-500 font-semibold tracking-wider">
                                  Log Entry ID
                                </div>
                                <div className="text-slate-300 font-mono text-[11px] bg-slate-900 px-2.5 py-1.5 rounded border border-slate-800 select-all">
                                  {log.id}
                                </div>
                              </div>

                              <div className="space-y-1">
                                <div className="text-[10px] uppercase text-slate-500 font-semibold tracking-wider">
                                  User-Agent Header
                                </div>
                                <div className="text-slate-300 font-mono text-[11px] bg-slate-900 px-2.5 py-1.5 rounded border border-slate-800 truncate select-all" title={log.user_agent}>
                                  {log.user_agent || '<empty>'}
                                </div>
                              </div>
                            </div>

                            <div className="space-y-1 pt-1">
                              <div className="text-[10px] uppercase text-slate-500 font-semibold tracking-wider">
                                Raw JSON Telemetry
                              </div>
                              <pre className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-[11px] font-mono text-cyan-300 overflow-x-auto">
                                {JSON.stringify(log, null, 2)}
                              </pre>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

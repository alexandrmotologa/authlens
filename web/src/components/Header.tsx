import React from 'react';
import { ServerStatus } from '../types';
import { ShieldCheck, RefreshCw, ExternalLink, Terminal } from 'lucide-react';

interface HeaderProps {
  status: ServerStatus | null;
  onRefresh: () => void;
}

export const Header: React.FC<HeaderProps> = ({ status, onRefresh }) => {
  return (
    <header className="border-b border-slate-800/80 bg-[#0A0E1A]/90 backdrop-blur-md sticky top-0 z-40 px-6 py-3.5">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        <div className="flex items-center space-x-3.5">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-indigo-600 p-[1.5px] shadow-lg shadow-cyan-500/20">
            <div className="w-full h-full bg-[#0A0E1A] rounded-[10px] flex items-center justify-center">
              <img src="/logo.svg" alt="AuthLens" className="w-6 h-6" />
            </div>
          </div>
          <div>
            <div className="flex items-center space-x-2.5">
              <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-1.5">
                AuthLens
                <span className="text-xs px-2 py-0.5 rounded-full font-mono font-medium bg-cyan-950/80 text-cyan-400 border border-cyan-800/60">
                  v{status?.version || '1.0.0'}
                </span>
              </h1>
            </div>
            <p className="text-xs text-slate-400">
              Local OIDC Provider, PKCE Handshake Tracer &amp; JWT Security Studio
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <div className="hidden md:flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs font-mono text-slate-300">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="text-slate-400">Provider:</span>
            <span className="text-emerald-400 font-semibold">{status?.base_url || 'http://127.0.0.1:9099'}</span>
          </div>

          <a
            href="/.well-known/openid-configuration"
            target="_blank"
            rel="noreferrer"
            className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 hover:text-white border border-slate-700 text-xs transition"
          >
            <span>Discovery</span>
            <ExternalLink className="w-3.5 h-3.5 text-slate-400" />
          </a>

          <a
            href="/.well-known/jwks.json"
            target="_blank"
            rel="noreferrer"
            className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 hover:text-white border border-slate-700 text-xs transition"
          >
            <span>JWKS</span>
            <ExternalLink className="w-3.5 h-3.5 text-slate-400" />
          </a>

          <button
            onClick={onRefresh}
            title="Refresh Server Telemetry"
            className="p-2 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-white border border-slate-700 transition"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
};

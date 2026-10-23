import React, { useState, useEffect } from 'react';
import { ServerStatus } from './types';
import { Header } from './components/Header';
import { OverviewPanel } from './components/OverviewPanel';
import { PersonaPanel } from './components/PersonaPanel';
import { PkcePanel } from './components/PkcePanel';
import { JwtPanel } from './components/JwtPanel';
import { FuzzerPanel } from './components/FuzzerPanel';
import { KeysPanel } from './components/KeysPanel';
import { Globe, Users, Activity, FileCode, Bug, Key } from 'lucide-react';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'overview' | 'personas' | 'pkce' | 'jwt' | 'fuzzer' | 'keys'>('overview');
  const [status, setStatus] = useState<ServerStatus | null>(null);
  const [selectedTokenForInspection, setSelectedTokenForInspection] = useState<string>('');

  const fetchStatus = async () => {
    try {
      const res = await fetch('/api/status');
      if (res.ok) {
        const data = await res.json();
        setStatus(data);
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 15000);
    return () => clearInterval(interval);
  }, []);

  const handleInspectToken = (token: string) => {
    setSelectedTokenForInspection(token);
    setActiveTab('jwt');
  };

  const navItems = [
    { id: 'overview', label: 'Overview & Endpoints', icon: Globe },
    { id: 'personas', label: 'Personas & Tokens', icon: Users },
    { id: 'pkce', label: 'PKCE Tracer', icon: Activity },
    { id: 'jwt', label: 'Offline JWT Studio', icon: FileCode },
    { id: 'fuzzer', label: 'Security Fuzzer', icon: Bug },
    { id: 'keys', label: 'Keystore & JWKS', icon: Key },
  ] as const;

  return (
    <div className="min-h-screen flex flex-col bg-[#070A12] text-slate-100">
      <Header status={status} onRefresh={fetchStatus} />

      {/* Main Tab Navigation */}
      <div className="border-b border-slate-800/80 bg-[#0B0F19]/60 backdrop-blur-sm sticky top-[69px] z-30 px-6">
        <div className="max-w-7xl mx-auto flex items-center space-x-1 overflow-x-auto py-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-medium whitespace-nowrap transition ${
                  isActive
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Panel Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-6">
        {activeTab === 'overview' && <OverviewPanel status={status} />}
        {activeTab === 'personas' && (
          <PersonaPanel
            baseURL={status?.base_url || 'http://127.0.0.1:9099'}
            onInspectToken={handleInspectToken}
          />
        )}
        {activeTab === 'pkce' && (
          <PkcePanel baseURL={status?.base_url || 'http://127.0.0.1:9099'} />
        )}
        {activeTab === 'jwt' && (
          <JwtPanel initialToken={selectedTokenForInspection} />
        )}
        {activeTab === 'fuzzer' && (
          <FuzzerPanel onInspectToken={handleInspectToken} />
        )}
        {activeTab === 'keys' && (
          <KeysPanel status={status} onRefresh={fetchStatus} />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-[#0B0F19] px-6 py-4 mt-auto">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-2">
          <div className="flex items-center space-x-2">
            <span>AuthLens</span>
            <span>&bull;</span>
            <span>Local OIDC Provider &amp; Security Lab</span>
          </div>
          <div className="flex items-center space-x-4">
            <span className="font-mono">Port: {status?.port || 9099}</span>
            <span>&bull;</span>
            <span>MIT License &copy; 2026 Alexandr Motologa</span>
          </div>
        </div>
      </footer>
    </div>
  );
};

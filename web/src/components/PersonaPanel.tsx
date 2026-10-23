import React, { useState, useEffect } from 'react';
import { Persona } from '../types';
import { UserCheck, Shield, AlertOctagon, Plus, Copy, Check, Terminal, ExternalLink, Key, RefreshCw } from 'lucide-react';

interface PersonaPanelProps {
  baseURL: string;
  onInspectToken: (token: string) => void;
}

export const PersonaPanel: React.FC<PersonaPanelProps> = ({ baseURL, onInspectToken }) => {
  const [personas, setPersonas] = useState<Persona[]>([]);
  const [selectedPersonaId, setSelectedPersonaId] = useState<string>('admin');
  const [selectedAlg, setSelectedAlg] = useState<string>('RS256');
  const [generatedToken, setGeneratedToken] = useState<string>('');
  const [tokenCurl, setTokenCurl] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // New persona modal state
  const [showNewModal, setShowNewModal] = useState<boolean>(false);
  const [newId, setNewId] = useState<string>('');
  const [newName, setNewName] = useState<string>('');
  const [newEmail, setNewEmail] = useState<string>('');
  const [newRole, setNewRole] = useState<string>('analyst');

  useEffect(() => {
    fetchPersonas();
  }, []);

  useEffect(() => {
    if (selectedPersonaId) {
      generateTokenForPersona(selectedPersonaId, selectedAlg);
    }
  }, [selectedPersonaId, selectedAlg]);

  const fetchPersonas = async () => {
    try {
      const res = await fetch('/api/personas');
      if (res.ok) {
        const data = await res.json();
        setPersonas(data);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const generateTokenForPersona = async (id: string, alg: string) => {
    setLoading(true);
    try {
      const res = await fetch(`/api/personas/${id}/token?alg=${alg}`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setGeneratedToken(data.access_token);
        setTokenCurl(data.curl || `curl -H "Authorization: Bearer ${data.access_token}" ${baseURL}/userinfo`);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateCustom = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newId || !newName || !newEmail) return;

    try {
      const res = await fetch('/api/personas', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: newId.toLowerCase().replace(/\s+/g, '_'),
          sub: 'usr_' + newId.toLowerCase(),
          name: newName,
          email: newEmail,
          email_verified: true,
          roles: [newRole],
          permissions: ['read'],
          scopes: ['openid', 'profile', 'email'],
          status: 'active',
        }),
      });

      if (res.ok) {
        await fetchPersonas();
        setSelectedPersonaId(newId.toLowerCase());
        setShowNewModal(false);
        setNewId('');
        setNewName('');
        setNewEmail('');
      }
    } catch (e) {
      console.error(e);
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const activePersona = personas.find((p) => p.id === selectedPersonaId);

  return (
    <div className="space-y-6">
      {/* Header controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-white tracking-tight">Persona Quick Switcher &amp; Token Studio</h2>
          <p className="text-xs text-slate-400">
            Generate authentic cryptographically signed Bearer tokens per user role in 1 click
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <select
            value={selectedAlg}
            onChange={(e) => setSelectedAlg(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-cyan-400 focus:outline-none focus:border-cyan-500"
          >
            <option value="RS256">Algorithm: RS256 (RSA 2048)</option>
            <option value="ES256">Algorithm: ES256 (ECDSA P-256)</option>
            <option value="EdDSA">Algorithm: EdDSA (Ed25519 OKP)</option>
            <option value="HS256">Algorithm: HS256 (HMAC Shared Secret)</option>
          </select>

          <button
            onClick={() => setShowNewModal(true)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium transition shadow-sm"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Custom Persona</span>
          </button>
        </div>
      </div>

      {/* Persona Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {personas.map((p) => {
          const isSelected = p.id === selectedPersonaId;
          const isAdmin = p.id === 'admin';
          const isSuspended = p.status === 'suspended';

          return (
            <div
              key={p.id}
              onClick={() => setSelectedPersonaId(p.id)}
              className={`cursor-pointer rounded-xl p-4 border transition relative overflow-hidden ${
                isSelected
                  ? 'bg-slate-900 border-cyan-500/80 shadow-lg shadow-cyan-950/40 ring-1 ring-cyan-500/30'
                  : 'bg-[#0B0F19] border-slate-800 hover:border-slate-700 hover:bg-slate-900/60'
              }`}
            >
              {isSelected && (
                <div className="absolute top-0 right-0 w-16 h-16 pointer-events-none">
                  <div className="absolute transform rotate-45 bg-cyan-500 text-[#070A12] text-[9px] font-bold py-0.5 right-[-35px] top-[14px] w-[120px] text-center shadow-sm">
                    ACTIVE
                  </div>
                </div>
              )}

              <div className="flex items-start gap-3">
                <div
                  className={`w-10 h-10 rounded-xl flex items-center justify-center ${
                    isAdmin
                      ? 'bg-rose-950/60 text-rose-400 border border-rose-800/60'
                      : isSuspended
                      ? 'bg-amber-950/60 text-amber-400 border border-amber-800/60'
                      : 'bg-cyan-950/60 text-cyan-400 border border-cyan-800/60'
                  }`}
                >
                  {isAdmin ? (
                    <Shield className="w-5 h-5" />
                  ) : isSuspended ? (
                    <AlertOctagon className="w-5 h-5" />
                  ) : (
                    <UserCheck className="w-5 h-5" />
                  )}
                </div>

                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-bold text-white">{p.name}</h3>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                        isSuspended
                          ? 'bg-amber-950 text-amber-400 border border-amber-800'
                          : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                      }`}
                    >
                      {p.status}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 font-mono">{p.email}</p>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-wrap gap-1.5">
                {p.roles.map((r) => (
                  <span key={r} className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300">
                    role:{r}
                  </span>
                ))}
                {p.permissions?.length > 0 && (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-950/80 text-indigo-300 border border-indigo-800/50">
                    perm:{p.permissions.join(',')}
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Generated Token Showcase */}
      {activePersona && (
        <div className="rounded-xl border border-slate-800 bg-[#0B0F19] overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Key className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-white">
                Live Bearer Token for <span className="text-cyan-400 font-mono">{activePersona.name}</span>
              </h3>
              <span className="text-xs font-mono text-slate-500">({selectedAlg} Signed)</span>
            </div>

            <div className="flex items-center space-x-2">
              <button
                onClick={() => generateTokenForPersona(activePersona.id, selectedAlg)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
                <span>Re-issue</span>
              </button>
              <button
                onClick={() => onInspectToken(generatedToken)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-950/80 hover:bg-indigo-900 border border-indigo-700 text-indigo-300 text-xs font-medium transition"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                <span>Inspect in JWT Studio</span>
              </button>
            </div>
          </div>

          <div className="p-5 space-y-4">
            {/* Raw Token Box */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>Bearer Token (Ready to paste into Postman, curl, or authorization headers):</span>
                <button
                  onClick={() => copyToClipboard(generatedToken, 'raw_token')}
                  className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 font-medium transition"
                >
                  {copiedKey === 'raw_token' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>Copy Token</span>
                </button>
              </div>
              <div className="relative">
                <textarea
                  readOnly
                  rows={3}
                  value={generatedToken}
                  className="w-full p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 selection:bg-cyan-500/30 break-all resize-none focus:outline-none"
                />
              </div>
            </div>

            {/* cURL Command Box */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span className="flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Ready-to-run cURL command (tests local /userinfo):</span>
                </span>
                <button
                  onClick={() => copyToClipboard(tokenCurl, 'curl_cmd')}
                  className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 font-medium transition"
                >
                  {copiedKey === 'curl_cmd' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>Copy cURL</span>
                </button>
              </div>
              <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto">
                <code>{tokenCurl}</code>
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* New Persona Modal */}
      {showNewModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#0B0F19] border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-bold text-white">Create Custom Persona</h3>
              <button
                onClick={() => setShowNewModal(false)}
                className="text-slate-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateCustom} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Identifier (ID)</label>
                <input
                  type="text"
                  required
                  placeholder="auditor"
                  value={newId}
                  onChange={(e) => setNewId(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Full Name</label>
                <input
                  type="text"
                  required
                  placeholder="Dave Auditor"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Email Address</label>
                <input
                  type="email"
                  required
                  placeholder="auditor@local.test"
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Primary Role</label>
                <input
                  type="text"
                  required
                  placeholder="security_auditor"
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="pt-2 flex items-center justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setShowNewModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs transition shadow-sm"
                >
                  Create Persona
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

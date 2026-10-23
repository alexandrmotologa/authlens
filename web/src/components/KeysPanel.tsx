import React, { useState, useEffect } from 'react';
import { ServerStatus } from '../types';
import { Key, RefreshCw, Copy, Check, Download, ShieldCheck, Lock } from 'lucide-react';

interface KeysPanelProps {
  status: ServerStatus | null;
  onRefresh: () => void;
}

export const KeysPanel: React.FC<KeysPanelProps> = ({ status, onRefresh }) => {
  const [jwksData, setJwksData] = useState<any>(null);
  const [keysExport, setKeysExport] = useState<{ rsa_public_pem: string; ec_public_pem: string } | null>(null);
  const [rotating, setRotating] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  useEffect(() => {
    fetchKeys();
  }, []);

  const fetchKeys = async () => {
    try {
      const [jwksRes, exportRes] = await Promise.all([
        fetch('/.well-known/jwks.json'),
        fetch('/api/keys/export'),
      ]);
      if (jwksRes.ok) setJwksData(await jwksRes.json());
      if (exportRes.ok) setKeysExport(await exportRes.json());
    } catch (e) {
      console.error(e);
    }
  };

  const handleRotate = async () => {
    setRotating(true);
    try {
      const res = await fetch('/api/keys/rotate', { method: 'POST' });
      if (res.ok) {
        await fetchKeys();
        onRefresh();
      }
    } catch (e) {
      console.error(e);
    } finally {
      setRotating(false);
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header and rotation trigger */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-white tracking-tight">Cryptographic Keystore &amp; JWKS Explorer</h2>
          <p className="text-xs text-slate-400">
            Ephemeral and rotated asymmetric signing keys published at RFC 7517 <code className="text-cyan-400 font-mono">/.well-known/jwks.json</code>
          </p>
        </div>

        <button
          onClick={handleRotate}
          disabled={rotating}
          className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-xs shadow-md shadow-indigo-600/20 transition disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${rotating ? 'animate-spin' : ''}`} />
          <span>Rotate Signing Keys</span>
        </button>
      </div>

      {/* Active Keys Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* RSA Key */}
        <div className="rounded-xl border border-slate-800 bg-[#0B0F19] p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-white">Active RSA 2048 Keypair</h3>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-cyan-950 text-cyan-400 border border-cyan-800">
              RS256
            </span>
          </div>

          <div className="space-y-1.5 text-xs font-mono">
            <div className="flex justify-between py-1 border-b border-slate-800/60">
              <span className="text-slate-400">Key ID (kid):</span>
              <span className="text-white font-semibold">{status?.active_rsa_kid}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/60">
              <span className="text-slate-400">Key Type:</span>
              <span className="text-slate-300">RSA (2048-bit)</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/60">
              <span className="text-slate-400">Public Exponent (e):</span>
              <span className="text-slate-300">AQAB (65537)</span>
            </div>
          </div>

          {keysExport?.rsa_public_pem && (
            <div className="pt-2">
              <button
                onClick={() => copyToClipboard(keysExport.rsa_public_pem, 'rsa_pem')}
                className="w-full inline-flex items-center justify-center gap-1.5 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-900 border border-slate-800 text-xs font-mono text-cyan-400 transition"
              >
                {copiedKey === 'rsa_pem' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>Copy RSA Public Key PEM</span>
              </button>
            </div>
          )}
        </div>

        {/* ECDSA Key */}
        <div className="rounded-xl border border-slate-800 bg-[#0B0F19] p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-indigo-400" />
              <h3 className="text-sm font-bold text-white">Active ECDSA P-256 Keypair</h3>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-indigo-950 text-indigo-400 border border-indigo-800">
              ES256
            </span>
          </div>

          <div className="space-y-1.5 text-xs font-mono">
            <div className="flex justify-between py-1 border-b border-slate-800/60">
              <span className="text-slate-400">Key ID (kid):</span>
              <span className="text-white font-semibold">{status?.active_ec_kid}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/60">
              <span className="text-slate-400">Key Type:</span>
              <span className="text-slate-300">EC (secp256r1 / P-256)</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/60">
              <span className="text-slate-400">Curve:</span>
              <span className="text-slate-300">P-256</span>
            </div>
          </div>

          {keysExport?.ec_public_pem && (
            <div className="pt-2">
              <button
                onClick={() => copyToClipboard(keysExport.ec_public_pem, 'ec_pem')}
                className="w-full inline-flex items-center justify-center gap-1.5 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-900 border border-slate-800 text-xs font-mono text-indigo-400 transition"
              >
                {copiedKey === 'ec_pem' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>Copy ECDSA Public Key PEM</span>
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Raw JWKS JSON view */}
      <div className="rounded-xl border border-slate-800 bg-[#0B0F19] overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Key className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-white">Live JWKS Payload (RFC 7517)</h3>
          </div>
          {jwksData && (
            <button
              onClick={() => copyToClipboard(JSON.stringify(jwksData, null, 2), 'jwks_json')}
              className="inline-flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 font-mono transition"
            >
              {copiedKey === 'jwks_json' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>Copy JSON</span>
            </button>
          )}
        </div>

        <div className="p-4">
          <pre className="p-4 rounded-lg bg-slate-950 border border-slate-800/80 text-xs font-mono text-cyan-300 overflow-x-auto max-h-96">
            <code>{jwksData ? JSON.stringify(jwksData, null, 2) : 'Loading JWKS...'}</code>
          </pre>
        </div>
      </div>
    </div>
  );
};

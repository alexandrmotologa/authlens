import React, { useState, useEffect } from 'react';
import { DecodedJWT, ValidationResult } from '../types';
import { ShieldCheck, ShieldAlert, Clock, Copy, Check, Lock, Edit3, RefreshCw, KeyRound, AlertTriangle } from 'lucide-react';

interface JwtPanelProps {
  initialToken?: string;
}

export const JwtPanel: React.FC<JwtPanelProps> = ({ initialToken }) => {
  const [tokenInput, setTokenInput] = useState<string>(initialToken || '');
  const [decoded, setDecoded] = useState<DecodedJWT | null>(null);
  const [validation, setValidation] = useState<ValidationResult | null>(null);
  const [customKey, setCustomKey] = useState<string>('');
  const [showCustomKey, setShowCustomKey] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Payload editor
  const [isEditingPayload, setIsEditingPayload] = useState<boolean>(false);
  const [editablePayloadStr, setEditablePayloadStr] = useState<string>('');
  const [signAlg, setSignAlg] = useState<string>('RS256');
  const [signing, setSigning] = useState<boolean>(false);

  useEffect(() => {
    if (initialToken) {
      setTokenInput(initialToken);
      decodeAndVerify(initialToken, customKey);
    }
  }, [initialToken]);

  const decodeAndVerify = async (token: string, keyPem?: string) => {
    if (!token.trim()) {
      setDecoded(null);
      setValidation(null);
      return;
    }

    try {
      // 1. Decode offline
      const decRes = await fetch('/api/jwt/decode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      });
      if (decRes.ok) {
        const decData: DecodedJWT = await decRes.json();
        setDecoded(decData);
        setEditablePayloadStr(JSON.stringify(decData.payload, null, 2));
      }

      // 2. Verify cryptographically offline
      const verRes = await fetch('/api/jwt/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, custom_key: keyPem }),
      });
      if (verRes.ok) {
        const verData: ValidationResult = await verRes.json();
        setValidation(verData);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleTokenChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const val = e.target.value;
    setTokenInput(val);
    decodeAndVerify(val, customKey);
  };

  const handleCustomKeyChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const val = e.target.value;
    setCustomKey(val);
    decodeAndVerify(tokenInput, val);
  };

  const handleSignEdited = async () => {
    setSigning(true);
    try {
      const parsedClaims = JSON.parse(editablePayloadStr);
      const res = await fetch('/api/jwt/sign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          claims: parsedClaims,
          algorithm: signAlg,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setTokenInput(data.token);
        setIsEditingPayload(false);
        decodeAndVerify(data.token, customKey);
      }
    } catch (e) {
      alert('Invalid JSON in claims payload');
    } finally {
      setSigning(false);
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header and explanation */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold text-white tracking-tight">Offline JWT Cryptographic Studio</h2>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-emerald-950 text-emerald-400 border border-emerald-800">
              100% Offline &bull; Zero Network Leaks
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Parse, audit expiration, inspect signatures, and verify cryptographic integrity locally
          </p>
        </div>

        <button
          onClick={() => setShowCustomKey(!showCustomKey)}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono transition"
        >
          <KeyRound className="w-3.5 h-3.5 text-cyan-400" />
          <span>{showCustomKey ? 'Hide Custom Key' : 'Verify with Custom Key/PEM'}</span>
        </button>
      </div>

      {/* Custom Key Drawer */}
      {showCustomKey && (
        <div className="p-4 rounded-xl border border-slate-800 bg-[#0B0F19] space-y-2">
          <label className="block text-xs font-medium text-slate-300">
            Custom RSA / ECDSA Public Key PEM or HMAC Secret (Overrides local AuthLens keys)
          </label>
          <textarea
            rows={4}
            value={customKey}
            onChange={handleCustomKeyChange}
            placeholder="-----BEGIN PUBLIC KEY-----&#10;MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...&#10;-----END PUBLIC KEY-----"
            className="w-full p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
          />
        </div>
      )}

      {/* Token Input Field */}
      <div className="rounded-xl border border-slate-800 bg-[#0B0F19] p-4 space-y-2">
        <div className="flex items-center justify-between text-xs text-slate-400">
          <span>Paste JWT String:</span>
          {tokenInput && (
            <button
              onClick={() => copyToClipboard(tokenInput, 'input_tok')}
              className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 transition"
            >
              {copiedKey === 'input_tok' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>Copy</span>
            </button>
          )}
        </div>
        <textarea
          rows={3}
          value={tokenInput}
          onChange={handleTokenChange}
          placeholder="eyJhbGciOiJSUzI1NiIsImtpZCI6ImF1dGhzZWNyZXQiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
          className="w-full p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500 selection:bg-cyan-500/30"
        />
      </div>

      {/* Validation Status & Breakdown */}
      {decoded && (
        <div className="space-y-6">
          {/* Status Alert Banner */}
          <div
            className={`rounded-xl p-4 border flex items-center justify-between gap-4 ${
              validation?.valid
                ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-300'
                : 'bg-rose-950/40 border-rose-800/80 text-rose-300'
            }`}
          >
            <div className="flex items-center gap-3">
              <div
                className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 ${
                  validation?.valid ? 'bg-emerald-900/60 text-emerald-400' : 'bg-rose-900/60 text-rose-400'
                }`}
              >
                {validation?.valid ? <ShieldCheck className="w-5 h-5" /> : <ShieldAlert className="w-5 h-5" />}
              </div>
              <div className="space-y-0.5">
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-bold">
                    {validation?.valid ? 'Signature Cryptographically Verified' : 'Cryptographic Verification Failed'}
                  </h3>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-black/40">
                    Source: {validation?.key_source || 'unknown'}
                  </span>
                </div>
                <p className="text-xs opacity-90">
                  {validation?.valid
                    ? `Token signed with active ${validation.algorithm} key (${validation.key_id || 'no kid'}). All signatures and temporal claims are valid.`
                    : validation?.error || 'Token signature could not be verified against public keys.'}
                </p>
              </div>
            </div>

            {decoded.expires_at && (
              <div className="hidden md:flex flex-col items-end text-xs font-mono">
                <span className="text-slate-400">Time-To-Live:</span>
                <span className={`font-bold ${decoded.is_expired ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {decoded.is_expired ? 'EXPIRED' : `${decoded.ttl_seconds}s remaining`}
                </span>
              </div>
            )}
          </div>

          {/* Three-Color Segmented JWT Visualizer */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* 1. Header (Red) */}
            <div className="rounded-xl border border-rose-900/60 bg-[#0B0F19] overflow-hidden">
              <div className="px-4 py-3 border-b border-rose-900/60 bg-rose-950/30 flex items-center justify-between">
                <span className="text-xs font-bold text-rose-400 uppercase tracking-wider">
                  Header: Algorithm &amp; Type
                </span>
                <span className="text-[10px] font-mono text-rose-400/80">Segment 1</span>
              </div>
              <div className="p-4 space-y-2">
                <pre className="text-xs font-mono text-rose-300 overflow-x-auto">
                  {JSON.stringify(decoded.header, null, 2)}
                </pre>
              </div>
            </div>

            {/* 2. Payload (Purple) */}
            <div className="rounded-xl border border-purple-900/60 bg-[#0B0F19] overflow-hidden md:col-span-2">
              <div className="px-4 py-3 border-b border-purple-900/60 bg-purple-950/30 flex items-center justify-between">
                <span className="text-xs font-bold text-purple-400 uppercase tracking-wider">
                  Payload: Data Claims
                </span>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => setIsEditingPayload(!isEditingPayload)}
                    className="inline-flex items-center gap-1 text-[11px] text-purple-300 hover:text-white transition"
                  >
                    <Edit3 className="w-3 h-3" />
                    <span>{isEditingPayload ? 'Cancel Edit' : 'Edit Claims'}</span>
                  </button>
                  <span className="text-[10px] font-mono text-purple-400/80">Segment 2</span>
                </div>
              </div>
              <div className="p-4">
                {isEditingPayload ? (
                  <div className="space-y-3">
                    <textarea
                      rows={8}
                      value={editablePayloadStr}
                      onChange={(e) => setEditablePayloadStr(e.target.value)}
                      className="w-full p-3 rounded-lg bg-slate-950 border border-purple-800 text-xs font-mono text-purple-200 focus:outline-none"
                    />
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-slate-400">Re-sign with:</span>
                        <select
                          value={signAlg}
                          onChange={(e) => setSignAlg(e.target.value)}
                          className="px-2 py-1 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-purple-300"
                        >
                          <option value="RS256">RS256 (Local RSA Key)</option>
                          <option value="ES256">ES256 (Local ECDSA Key)</option>
                          <option value="HS256">HS256 (Local HMAC Key)</option>
                        </select>
                      </div>

                      <button
                        onClick={handleSignEdited}
                        disabled={signing}
                        className="px-3.5 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-medium transition shadow-sm"
                      >
                        {signing ? 'Signing...' : 'Re-sign Token'}
                      </button>
                    </div>
                  </div>
                ) : (
                  <pre className="text-xs font-mono text-purple-300 overflow-x-auto max-h-72">
                    {JSON.stringify(decoded.payload, null, 2)}
                  </pre>
                )}
              </div>
            </div>
          </div>

          {/* 3. Signature (Cyan) */}
          <div className="rounded-xl border border-cyan-900/60 bg-[#0B0F19] overflow-hidden">
            <div className="px-4 py-3 border-b border-cyan-900/60 bg-cyan-950/30 flex items-center justify-between">
              <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider">
                Cryptographic Signature
              </span>
              <span className="text-[10px] font-mono text-cyan-400/80">
                Segment 3 &bull; {decoded.signature_size_bytes} bytes
              </span>
            </div>
            <div className="p-4 space-y-2">
              <p className="text-xs text-slate-400">
                Computed by hashing <code className="text-rose-400">header</code> and <code className="text-purple-400">payload</code> with{' '}
                <span className="text-cyan-400 font-mono font-semibold">{decoded.algorithm}</span>:
              </p>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-400 break-all">
                {decoded.signature_raw || (
                  <span className="text-rose-400 italic">No signature present (alg: none or stripped)</span>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

import React, { useState } from 'react';
import { ServerStatus } from '../types';
import { Copy, Check, ExternalLink, Terminal, Shield, ArrowRight, Code, Download, Box } from 'lucide-react';

interface OverviewPanelProps {
  status: ServerStatus | null;
}

export const OverviewPanel: React.FC<OverviewPanelProps> = ({ status }) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [selectedSnippet, setSelectedSnippet] = useState<'nextauth' | 'express' | 'go' | 'python'>('nextauth');

  const baseURL = status?.base_url || 'http://127.0.0.1:9099';

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const endpoints = [
    {
      name: 'OIDC Discovery',
      path: '/.well-known/openid-configuration',
      method: 'GET',
      rfc: 'RFC 8414',
      desc: 'Automatic metadata discovery for clients, libraries, and frameworks',
    },
    {
      name: 'JWKS Keystore',
      path: '/.well-known/jwks.json',
      method: 'GET',
      rfc: 'RFC 7517 / RFC 8037',
      desc: 'Active and rotated RSA, ECDSA, and Ed25519 cryptographic public keys',
    },
    {
      name: 'Authorization Endpoint',
      path: '/oauth/authorize',
      method: 'GET / POST',
      rfc: 'OAuth 2.1',
      desc: 'PKCE challenge registration with interactive browser consent screen',
    },
    {
      name: 'Token Endpoint',
      path: '/oauth/token',
      method: 'POST',
      rfc: 'RFC 6749 / 7636',
      desc: 'Code exchange with code_verifier validation, issuing JWTs',
    },
    {
      name: 'UserInfo Endpoint',
      path: '/userinfo',
      method: 'GET',
      rfc: 'OIDC Core 1.0',
      desc: 'Returns claims for bearer-authenticated subjects',
    },
    {
      name: 'Token Introspection',
      path: '/oauth/introspect',
      method: 'POST',
      rfc: 'RFC 7662',
      desc: 'Resource server query to verify active token status',
    },
    {
      name: 'Token Revocation',
      path: '/oauth/revoke',
      method: 'POST',
      rfc: 'RFC 7009',
      desc: 'Token revocation endpoint',
    },
    {
      name: 'Mock Protected Sandbox',
      path: '/api/mock/protected',
      method: 'GET / POST',
      rfc: 'Resource Server',
      desc: 'Built-in protected API validating JWT signatures and role permissions',
    },
  ];

  const snippets = {
    nextauth: `// Auth.js / NextAuth provider configuration
export const authOptions = {
  providers: [
    {
      id: "authlens",
      name: "AuthLens Local",
      type: "oauth",
      wellKnown: "${baseURL}/.well-known/openid-configuration",
      authorization: { params: { scope: "openid profile email admin" } },
      clientId: "my-web-app",
      clientSecret: "local-dev-secret",
      idToken: true,
      checks: ["pkce", "state"],
      profile(profile) {
        return {
          id: profile.sub,
          name: profile.name,
          email: profile.email,
          roles: profile.roles,
        };
      },
    },
  ],
};`,
    express: `// Node.js Express JWT Middleware (jwks-rsa + express-oauth2-jwt-bearer)
const { auth } = require('express-oauth2-jwt-bearer');

const checkJwt = auth({
  issuerBaseURL: '${baseURL}',
  audience: '${baseURL}/api',
  tokenSigningAlg: 'RS256'
});

app.get('/api/protected', checkJwt, (req, res) => {
  res.json({ message: "Access granted", user: req.auth.payload });
});`,
    go: `// Go backend middleware using coreos/go-oidc/v3
import (
    "context"
    "github.com/coreos/go-oidc/v3/oidc"
)

provider, err := oidc.NewProvider(context.Background(), "${baseURL}")
if err != nil {
    log.Fatal(err)
}

verifier := provider.Verifier(&oidc.Config{
    ClientID: "my-backend-api",
})

idToken, err := verifier.Verify(ctx, rawTokenString)`,
    python: `# Python FastAPI with Authlib
from authlib.integrations.starlette_integration import OAuth

oauth = OAuth()
oauth.register(
    name='authlens',
    server_metadata_url='${baseURL}/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid profile email admin'}
)`,
  };

  return (
    <div className="space-y-6">
      {/* Hero Quick Start banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-slate-800 p-6">
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-cyan-950/70 border border-cyan-800/60 text-cyan-400 text-xs font-mono">
              <Shield className="w-3.5 h-3.5" />
              <span>Zero-Config Local Identity Provider</span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight">
              Stand-alone OIDC &amp; OAuth 2.1 Provider on port {status?.port || 9099}
            </h2>
            <p className="text-sm text-slate-300 max-w-2xl leading-relaxed">
              AuthLens eliminates cloud identity friction for local development. Point your backend or frontend auth client to{' '}
              <code className="text-cyan-300 font-mono bg-cyan-950/60 px-1.5 py-0.5 rounded text-xs">{baseURL}</code> for instant discovery, key retrieval, and token validation.
            </p>
          </div>

          <div className="flex flex-wrap gap-2.5">
            <button
              onClick={() => copyToClipboard(baseURL + '/.well-known/openid-configuration', 'disc_url')}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs shadow-lg shadow-cyan-600/20 transition"
            >
              {copiedKey === 'disc_url' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              <span>Copy Discovery URL</span>
            </button>
            <a
              href="/api/export/postman"
              download="authlens_postman_collection.json"
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-medium text-xs transition"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>Export Postman</span>
            </a>
            <a
              href="/api/export/bruno"
              download="authlens_bruno_collection.json"
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-medium text-xs transition"
            >
              <Download className="w-3.5 h-3.5 text-indigo-400" />
              <span>Export Bruno</span>
            </a>
          </div>
        </div>
      </div>

      {/* Endpoints Table */}
      <div className="rounded-xl border border-slate-800 bg-[#0B0F19] overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white">Standard OIDC &amp; OAuth 2.1 Endpoints</h3>
            <p className="text-xs text-slate-400">All endpoints adhere strictly to RFC specifications</p>
          </div>
          <span className="text-xs font-mono text-slate-400">{endpoints.length} active routes</span>
        </div>

        <div className="divide-y divide-slate-800/80 overflow-x-auto">
          {endpoints.map((ep) => (
            <div key={ep.path} className="px-5 py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-900/50 transition">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-white">{ep.name}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-slate-800 text-slate-300 border border-slate-700">
                    {ep.method}
                  </span>
                  <span className="text-[10px] font-mono text-slate-500">{ep.rfc}</span>
                </div>
                <p className="text-xs text-slate-400">{ep.desc}</p>
              </div>

              <div className="flex items-center gap-2 font-mono text-xs">
                <span className="text-cyan-400 bg-slate-950/70 border border-slate-800 px-2.5 py-1 rounded">
                  {ep.path}
                </span>
                <button
                  onClick={() => copyToClipboard(baseURL + ep.path, ep.path)}
                  title="Copy Full URL"
                  className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition"
                >
                  {copiedKey === ep.path ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
                <a
                  href={baseURL + ep.path}
                  target="_blank"
                  rel="noreferrer"
                  title="Open in new tab"
                  className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                </a>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Code Snippets Section */}
      <div className="rounded-xl border border-slate-800 bg-[#0B0F19] overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Code className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-white">Client &amp; Middleware Integration Snippets</h3>
          </div>

          <div className="flex items-center space-x-1.5 bg-slate-900/90 p-1 rounded-lg border border-slate-800">
            {(['nextauth', 'express', 'go', 'python'] as const).map((key) => (
              <button
                key={key}
                onClick={() => setSelectedSnippet(key)}
                className={`px-3 py-1 rounded-md text-xs font-medium transition ${
                  selectedSnippet === key
                    ? 'bg-cyan-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {key === 'nextauth' && 'NextAuth / Auth.js'}
                {key === 'express' && 'Node.js Express'}
                {key === 'go' && 'Golang OIDC'}
                {key === 'python' && 'Python FastAPI'}
              </button>
            ))}
          </div>
        </div>

        <div className="p-4 relative">
          <button
            onClick={() => copyToClipboard(snippets[selectedSnippet], 'snippet')}
            className="absolute top-7 right-7 inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono transition z-10"
          >
            {copiedKey === 'snippet' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>Copy</span>
          </button>
          <pre className="p-4 rounded-lg bg-slate-950 border border-slate-800/80 text-xs font-mono text-slate-300 overflow-x-auto leading-relaxed">
            <code>{snippets[selectedSnippet]}</code>
          </pre>
        </div>
      </div>
    </div>
  );
};

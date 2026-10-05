"use client";

import { Input, Label } from "@/components/brutal";

export type WebsocketConfig = {
  kind: "websocket";
  subprotocols: string[];
  origin_header?: string;
  auth_token_in_query?: string;
};

export const DEFAULT_WEBSOCKET_CONFIG: WebsocketConfig = {
  kind: "websocket",
  subprotocols: [],
  origin_header: "",
  auth_token_in_query: "",
};

export type WebsocketCredentials = {
  token: string;
  cookie: string;
};

export const EMPTY_WEBSOCKET_CREDS: WebsocketCredentials = {
  token: "", cookie: "",
};

export function WebsocketFormSection({
  value,
  onChange,
  name,
  setName,
  wsEndpoint,
  setWsEndpoint,
  rawSubprotocols,
  setRawSubprotocols,
  creds,
  setCreds,
}: {
  value: WebsocketConfig;
  onChange: (v: WebsocketConfig) => void;
  name: string;
  setName: (v: string) => void;
  wsEndpoint: string;
  setWsEndpoint: (v: string) => void;
  /** CSV / newline list of subprotocols — parsed into ``value.subprotocols``. */
  rawSubprotocols: string;
  setRawSubprotocols: (v: string) => void;
  creds: WebsocketCredentials;
  setCreds: (v: WebsocketCredentials) => void;
}) {
  function onSubprotocolsChange(raw: string) {
    setRawSubprotocols(raw);
    const sp = raw.split(/[,\n]/).map((s) => s.trim()).filter(Boolean);
    onChange({ ...value, subprotocols: sp });
  }

  return (
    <>
      <section>
        <div className="flex items-baseline gap-3 mb-5">
          <span className="eyebrow-gilt">WS1</span>
          <h2 className="font-display text-[18px] text-ink">WebSocket</h2>
        </div>
        <div className="grid md:grid-cols-2 gap-5">
          <div className="md:col-span-2">
            <Label>WebSocket endpoint</Label>
            <Input
              required
              type="url"
              placeholder="wss://realtime.example.com/socket"
              value={wsEndpoint}
              onChange={(e) => setWsEndpoint(e.target.value)}
            />
            <p className="mt-1.5 font-mono text-[11px] text-mist">
              Accepts <code>wss://</code> or <code>https://</code> origin (upgrade is negotiated at handshake).
            </p>
          </div>
          <div className="md:col-span-2">
            <Label>Name (optional)</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Chat realtime socket" />
          </div>
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-1">
          <span className="eyebrow-gilt">WS2</span>
          <h2 className="font-display text-[18px] text-ink">Handshake</h2>
        </div>
        <p className="text-[13px] text-slate italic mb-4">
          Configure the WS handshake the scanner sends. <code>Sec-WebSocket-Protocol</code> is sent
          when subprotocols are listed.
        </p>
        <div className="grid sm:grid-cols-2 gap-5">
          <div className="sm:col-span-2">
            <Label>Subprotocols (comma- or newline-separated, optional)</Label>
            <textarea
              rows={3}
              value={rawSubprotocols}
              onChange={(e) => onSubprotocolsChange(e.target.value)}
              placeholder="graphql-ws&#10;chat.v1"
              className="w-full font-mono text-[12px] bg-paper border border-hairline rounded-sm p-3 focus:outline-none focus:border-ink"
            />
          </div>
          <div>
            <Label>Origin header override (optional)</Label>
            <Input
              placeholder="https://app.example.com"
              value={value.origin_header ?? ""}
              onChange={(e) => onChange({ ...value, origin_header: e.target.value })}
            />
          </div>
          <div>
            <Label>Auth-token query parameter name (optional)</Label>
            <Input
              placeholder="access_token"
              value={value.auth_token_in_query ?? ""}
              onChange={(e) => onChange({ ...value, auth_token_in_query: e.target.value })}
            />
            <p className="mt-1.5 font-mono text-[11px] text-mist">
              If set, the scanner appends <code>?{value.auth_token_in_query || "access_token"}=&lt;token&gt;</code>.
            </p>
          </div>
        </div>
      </section>

      <hr className="rule" />

      <section>
        <div className="flex items-baseline gap-3 mb-1">
          <span className="eyebrow-gilt">WS3</span>
          <h2 className="font-display text-[18px] text-ink">Credentials (optional)</h2>
        </div>
        <p className="text-[13px] text-slate italic mb-6">Fernet-encrypted at rest.</p>
        <div className="grid sm:grid-cols-2 gap-5">
          <div>
            <Label>Bearer token</Label>
            <Input value={creds.token} onChange={(e) => setCreds({ ...creds, token: e.target.value })} autoComplete="off" />
          </div>
          <div>
            <Label>Cookie header</Label>
            <Input value={creds.cookie} onChange={(e) => setCreds({ ...creds, cookie: e.target.value })} autoComplete="off" />
          </div>
        </div>
      </section>
    </>
  );
}

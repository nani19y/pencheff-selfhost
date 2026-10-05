"use client";

import { Input } from "@/components/brutal";
import type { SupportedKind } from "@/components/register-target/target-types";

// One provider-aware form for the 6 network/identity kinds. Holds the full
// kind_config + kind_credentials drafts; the register page reads them on submit.
export type NIDraft = {
  config: Record<string, unknown>;
  creds: Record<string, unknown>;
};

export function defaultNIDraft(kind: SupportedKind): NIDraft {
  const base: Record<string, unknown> = { kind };
  if (kind === "tls_ssl")
    return { config: { ...base, source: "endpoint" }, creds: {} };
  if (kind === "dns")
    return { config: { ...base, provider: "generic" }, creds: {} };
  if (kind === "email_security")
    return { config: { ...base, provider: "generic" }, creds: {} };
  if (kind === "vpn")
    return { config: { ...base, vpn_type: "auto" }, creds: {} };
  if (kind === "idp")
    return { config: { ...base, provider: "generic_oidc" }, creds: {} };
  if (kind === "data_store")
    return { config: { ...base, engine: "auto" }, creds: {} };
  return { config: base, creds: {} };
}

const PROVIDERS: Record<string, { value: string; label: string }[]> = {
  tls_source: [
    { value: "endpoint", label: "Live endpoint" },
    { value: "upload", label: "Upload certificate (PEM)" },
    { value: "acm", label: "AWS ACM" },
    { value: "azure_keyvault", label: "Azure Key Vault" },
    { value: "gcp", label: "GCP Certificate Manager" },
    { value: "cloudflare", label: "Cloudflare" },
  ],
  dns: [
    { value: "generic", label: "Generic (authoritative NS)" },
    { value: "route53", label: "AWS Route 53" },
    { value: "cloudflare", label: "Cloudflare" },
    { value: "azure_dns", label: "Azure DNS" },
    { value: "gcp", label: "GCP Cloud DNS" },
  ],
  email: [
    { value: "generic", label: "Generic (DNS only)" },
    { value: "ses", label: "AWS SES" },
    { value: "resend", label: "Resend" },
    { value: "google_workspace", label: "Google Workspace" },
    { value: "azure_acs", label: "Azure ACS" },
  ],
  vpn: [
    { value: "auto", label: "Auto-detect" },
    { value: "openvpn", label: "OpenVPN" },
    { value: "wireguard", label: "WireGuard" },
    { value: "ipsec", label: "IPsec / IKE" },
    {
      value: "ssl_vpn",
      label: "SSL-VPN (Fortinet / Palo Alto / Pulse / Citrix)",
    },
    { value: "pptp", label: "PPTP" },
    { value: "remote_access", label: "Remote access (RDP/SSH/VNC)" },
  ],
  idp: [
    { value: "generic_oidc", label: "Generic OIDC" },
    { value: "okta", label: "Okta" },
    { value: "azure_ad", label: "Azure AD / Entra" },
    { value: "auth0", label: "Auth0" },
    { value: "workos", label: "WorkOS" },
    { value: "casdoor", label: "Casdoor" },
    { value: "saml", label: "SAML" },
    { value: "custom", label: "Custom provider" },
  ],
  engine: [
    { value: "auto", label: "Auto-detect" },
    { value: "redis", label: "Redis" },
    { value: "memcached", label: "Memcached" },
    { value: "mongodb", label: "MongoDB" },
    { value: "postgresql", label: "PostgreSQL" },
    { value: "mysql", label: "MySQL" },
    { value: "elasticsearch", label: "Elasticsearch" },
    { value: "mssql", label: "MSSQL" },
    { value: "couchdb", label: "CouchDB" },
    { value: "cassandra", label: "Cassandra" },
  ],
};

const label =
  "block font-mono text-[11px] uppercase tracking-[0.14em] text-slate";
const hint = "text-[12px] text-slate";

export function NetworkIdentityFormSection({
  kind,
  value,
  onChange,
}: {
  kind: SupportedKind;
  value: NIDraft;
  onChange: (d: NIDraft) => void;
}) {
  const cfg = value.config;
  const creds = value.creds;
  const setCfg = (patch: Record<string, unknown>) =>
    onChange({ ...value, config: { ...cfg, ...patch } });
  const setCreds = (patch: Record<string, unknown>) =>
    onChange({ ...value, creds: { ...creds, ...patch } });

  const Select = ({
    opts,
    val,
    onSel,
  }: {
    opts: { value: string; label: string }[];
    val: string;
    onSel: (v: string) => void;
  }) => (
    <select
      value={val}
      onChange={(e) => onSel(e.target.value)}
      className="w-full border border-hairline rounded-sm bg-vellum px-3 py-2 font-body text-[14px] text-ink"
    >
      {opts.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );

  const provider = String(cfg.provider ?? "");
  const source = String(cfg.source ?? "endpoint");

  return (
    <div className="space-y-4">
      {/* ── TLS/SSL ── */}
      {kind === "tls_ssl" && (
        <>
          <div className="space-y-2">
            <label className={label}>Certificate source</label>
            <Select
              opts={PROVIDERS.tls_source}
              val={source}
              onSel={(v) => setCfg({ source: v })}
            />
          </div>
          {source === "endpoint" && (
            <div className="space-y-2">
              <label className={label}>Host(s)</label>
              <Input
                value={String(cfg.hosts_text ?? "")}
                onChange={(e) =>
                  setCfg({
                    hosts_text: e.target.value,
                    hosts: e.target.value.split(/[\s,]+/).filter(Boolean),
                  })
                }
                placeholder="example.com  or  1.2.3.4  or  host:8443  (comma-separated)"
              />
              <p className={hint}>
                Defaults to port 443; append :port to override.
              </p>
            </div>
          )}
          {source === "upload" && (
            <div className="space-y-2">
              <label className={label}>Certificate (PEM)</label>
              <textarea
                rows={7}
                value={String(cfg.certificate_pem ?? "")}
                onChange={(e) => setCfg({ certificate_pem: e.target.value })}
                placeholder="-----BEGIN CERTIFICATE-----"
                className="w-full border border-hairline rounded-sm bg-vellum px-3 py-2 font-mono text-[12px]"
              />
              <input
                type="file"
                accept=".pem,.crt,.cer,.txt"
                onChange={async (e) => {
                  const f = e.target.files?.[0];
                  if (f) setCfg({ certificate_pem: await f.text() });
                }}
              />
            </div>
          )}
          {source === "acm" && (
            <div className="space-y-2">
              <label className={label}>ACM certificate ARN</label>
              <Input
                value={String(cfg.acm_certificate_arn ?? "")}
                onChange={(e) =>
                  setCfg({ acm_certificate_arn: e.target.value })
                }
                placeholder="arn:aws:acm:us-east-1:123…:certificate/…"
              />
              <AwsCreds creds={creds} setCreds={setCreds} />
            </div>
          )}
          {source === "cloudflare" && (
            <div className="space-y-2">
              <label className={label}>Cloudflare zone ID</label>
              <Input
                value={String(cfg.cloudflare_zone_id ?? "")}
                onChange={(e) => setCfg({ cloudflare_zone_id: e.target.value })}
                placeholder="zone id"
              />
              <label className={label}>Cloudflare API token</label>
              <Input
                type="password"
                value={String(creds.cloudflare_api_token ?? "")}
                onChange={(e) =>
                  setCreds({ cloudflare_api_token: e.target.value })
                }
              />
            </div>
          )}
          <Toggles
            cfg={cfg}
            setCfg={setCfg}
            keys={[
              ["check_protocols", "Protocols"],
              ["check_ciphers", "Cipher suites"],
              ["check_certificate", "Certificate"],
              ["check_hardening", "TLS hardening (HSTS/OCSP)"],
              ["run_ssl_labs", "SSL Labs grade (sends host to Qualys)"],
            ]}
          />
        </>
      )}

      {/* ── DNS ── */}
      {kind === "dns" && (
        <>
          <div className="space-y-2">
            <label className={label}>DNS provider</label>
            <Select
              opts={PROVIDERS.dns}
              val={provider || "generic"}
              onSel={(v) => setCfg({ provider: v })}
            />
          </div>
          <div className="space-y-2">
            <label className={label}>Domain</label>
            <Input
              value={String(cfg.domain ?? "")}
              onChange={(e) => setCfg({ domain: e.target.value })}
              placeholder="example.com"
            />
          </div>
          {provider === "route53" && (
            <>
              <div className="space-y-2">
                <label className={label}>Hosted zone ID</label>
                <Input
                  value={String(cfg.hosted_zone_id ?? "")}
                  onChange={(e) => setCfg({ hosted_zone_id: e.target.value })}
                />
              </div>
              <AwsCreds creds={creds} setCreds={setCreds} />
            </>
          )}
          {provider === "cloudflare" && (
            <>
              <div className="space-y-2">
                <label className={label}>Cloudflare zone ID</label>
                <Input
                  value={String(cfg.cloudflare_zone_id ?? "")}
                  onChange={(e) =>
                    setCfg({ cloudflare_zone_id: e.target.value })
                  }
                />
              </div>
              <div className="space-y-2">
                <label className={label}>Cloudflare API token</label>
                <Input
                  type="password"
                  value={String(creds.cloudflare_api_token ?? "")}
                  onChange={(e) =>
                    setCreds({ cloudflare_api_token: e.target.value })
                  }
                />
              </div>
            </>
          )}
          <Toggles
            cfg={cfg}
            setCfg={setCfg}
            keys={[
              ["zone_transfer", "Zone transfer (AXFR)"],
              ["subdomain_enum", "Subdomain enumeration"],
              ["check_dnssec", "DNSSEC"],
              ["check_caa", "CAA record"],
              ["check_takeover", "Subdomain takeover"],
            ]}
          />
        </>
      )}

      {/* ── Email ── */}
      {kind === "email_security" && (
        <>
          <div className="space-y-2">
            <label className={label}>Email provider</label>
            <Select
              opts={PROVIDERS.email}
              val={provider || "generic"}
              onSel={(v) => setCfg({ provider: v })}
            />
          </div>
          <div className="space-y-2">
            <label className={label}>Domain</label>
            <Input
              value={String(cfg.domain ?? "")}
              onChange={(e) => setCfg({ domain: e.target.value })}
              placeholder="example.com"
            />
          </div>
          {provider === "ses" && <AwsCreds creds={creds} setCreds={setCreds} />}
          {provider === "resend" && (
            <div className="space-y-2">
              <label className={label}>Resend API key</label>
              <Input
                type="password"
                value={String(creds.resend_api_key ?? "")}
                onChange={(e) => setCreds({ resend_api_key: e.target.value })}
              />
            </div>
          )}
          <Toggles
            cfg={cfg}
            setCfg={setCfg}
            keys={[
              ["check_mta_sts", "MTA-STS"],
              ["check_tls_rpt", "TLS-RPT"],
              ["check_bimi", "BIMI"],
            ]}
          />
        </>
      )}

      {/* ── VPN ── */}
      {kind === "vpn" && (
        <>
          <div className="space-y-2">
            <label className={label}>VPN type</label>
            <Select
              opts={PROVIDERS.vpn}
              val={String(cfg.vpn_type ?? "auto")}
              onSel={(v) => setCfg({ vpn_type: v })}
            />
          </div>
          <div className="space-y-2">
            <label className={label}>Host(s)</label>
            <Input
              value={String(cfg.hosts_text ?? "")}
              onChange={(e) =>
                setCfg({
                  hosts_text: e.target.value,
                  hosts: e.target.value.split(/[\s,]+/).filter(Boolean),
                })
              }
              placeholder="vpn.example.com  or  1.2.3.4  (comma-separated)"
            />
            <p className={hint}>
              Fingerprints VPN/remote-access services and flags exposed
              gateways.
            </p>
          </div>
        </>
      )}

      {/* ── IdP ── */}
      {kind === "idp" && (
        <>
          <div className="space-y-2">
            <label className={label}>Identity provider</label>
            <Select
              opts={PROVIDERS.idp}
              val={provider || "generic_oidc"}
              onSel={(v) => setCfg({ provider: v })}
            />
          </div>
          <div className="space-y-2">
            <label className={label}>Issuer URL</label>
            <Input
              value={String(cfg.issuer_url ?? "")}
              onChange={(e) => setCfg({ issuer_url: e.target.value })}
              placeholder="https://your-org.okta.com  /  https://login.microsoftonline.com/<tenant>/v2.0"
            />
          </div>
          <div className="space-y-2">
            <label className={label}>SAML metadata URL (optional)</label>
            <Input
              value={String(cfg.saml_metadata_url ?? "")}
              onChange={(e) => setCfg({ saml_metadata_url: e.target.value })}
              placeholder="https://…/app/…/sso/saml/metadata"
            />
          </div>
          {(provider === "okta" ||
            provider === "auth0" ||
            provider === "workos" ||
            provider === "casdoor") && (
            <div className="space-y-2 border-t border-hairline pt-3">
              <p className={hint}>
                Optional: an admin API token unlocks provider policy checks
                (MFA, password, brute-force).
              </p>
              <label className={label}>Org domain</label>
              <Input
                value={String(cfg.org_domain ?? "")}
                onChange={(e) => setCfg({ org_domain: e.target.value })}
                placeholder="your-org.okta.com  /  tenant.auth0.com"
              />
              <label className={label}>Admin API token</label>
              <Input
                type="password"
                value={String(creds.api_token ?? "")}
                onChange={(e) =>
                  setCreds({
                    api_token: e.target.value,
                    org_domain: cfg.org_domain,
                  })
                }
              />
            </div>
          )}
        </>
      )}

      {/* ── Data store ── */}
      {kind === "data_store" && (
        <>
          <div className="space-y-2">
            <label className={label}>Engine</label>
            <Select
              opts={PROVIDERS.engine}
              val={String(cfg.engine ?? "auto")}
              onSel={(v) => setCfg({ engine: v })}
            />
          </div>
          <div className="space-y-2">
            <label className={label}>Host(s)</label>
            <Input
              value={String(cfg.hosts_text ?? "")}
              onChange={(e) =>
                setCfg({
                  hosts_text: e.target.value,
                  hosts: e.target.value.split(/[\s,]+/).filter(Boolean),
                })
              }
              placeholder="db.example.com:6379  or  1.2.3.4  (comma-separated; port optional)"
            />
            <p className={hint}>
              Checks exposure, unauthenticated access, TLS, and version/EOL.
            </p>
          </div>
        </>
      )}
    </div>
  );
}

function AwsCreds({
  creds,
  setCreds,
}: {
  creds: Record<string, unknown>;
  setCreds: (p: Record<string, unknown>) => void;
}) {
  return (
    <div className="space-y-2 border-t border-hairline pt-3">
      <p className={hint}>
        AWS credentials (read-only) enable provider enrichment.
      </p>
      <label className={label}>Access key ID</label>
      <Input
        value={String(creds.aws_access_key_id ?? "")}
        onChange={(e) => setCreds({ aws_access_key_id: e.target.value })}
      />
      <label className={label}>Secret access key</label>
      <Input
        type="password"
        value={String(creds.aws_secret_access_key ?? "")}
        onChange={(e) => setCreds({ aws_secret_access_key: e.target.value })}
      />
      <label className={label}>Region (optional)</label>
      <Input
        value={String(creds.aws_region ?? "")}
        onChange={(e) => setCreds({ aws_region: e.target.value })}
        placeholder="us-east-1"
      />
    </div>
  );
}

function Toggles({
  cfg,
  setCfg,
  keys,
}: {
  cfg: Record<string, unknown>;
  setCfg: (p: Record<string, unknown>) => void;
  keys: [string, string][];
}) {
  return (
    <div className="flex flex-wrap gap-x-5 gap-y-2 pt-1">
      {keys.map(([k, lbl]) => (
        <label
          key={k}
          className="inline-flex items-center gap-2 text-[13px] text-graphite"
        >
          <input
            type="checkbox"
            checked={cfg[k] !== false}
            onChange={(e) => setCfg({ [k]: e.target.checked })}
          />
          {lbl}
        </label>
      ))}
    </div>
  );
}

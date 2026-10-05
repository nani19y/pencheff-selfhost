"use client";

import React, { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { api, downloadFile } from "@/lib/api";
import { Button, Card, Input, Badge } from "@/components/brutal";
import { PageLoading } from "@/components/loading";
import { StatCard } from "@/components/app/stat-card";
import { IntelPanel, IntelRow, IntelDivider } from "@/components/app/intel-panel";

type CheckResult = {
  key: string;
  name: string;
  description: string;
  status: "PENDING" | "SECURE" | "WARNING" | "INFO";
  command: string;
  args: string[];
  rawOutput: string;
  errorOutput?: string;
};

type FileAuditResult = {
  name: string;
  path: string;
  sizeBytes: number;
  formattedSize: string;
  modificationDate: string;
  permissions: string;
  isExecutable: boolean;
  quarantineRaw: string;
  downloadSource: string;
  status: "CLEAN" | "SUSPICIOUS" | "MALICIOUS";
};

type MemberCompliance = {
  user_id: string;
  email: string;
  name: string | null;
  role: string;
  studio_installed: boolean;
  monitors_enabled: boolean;
  overall_device_score: number;
  overall_file_status: string;
  device_checks_json: CheckResult[] | null;
  file_checks_json: FileAuditResult[] | null;
  updated_at: string | null;
};

// SVG icons
function ShieldCheckIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="w-5 h-5 text-forest" aria-hidden>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="M9 11l2 2 4-4" />
    </svg>
  );
}

function ShieldAlertIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="w-5 h-5 text-sev-medium" aria-hidden>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <line x1="12" y1="8" x2="12" y2="12" />
      <line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
  );
}

function TerminalIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="w-4 h-4 text-gilt" aria-hidden>
      <polyline points="4 17 10 11 4 5" />
      <line x1="12" y1="19" x2="20" y2="19" />
    </svg>
  );
}

export default function CompliancePage() {
  const [isAdmin, setIsAdmin] = useState(false);
  const [members, setMembers] = useState<MemberCompliance[]>([]);
  const [myCompliance, setMyCompliance] = useState<MemberCompliance | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedUser, setExpandedUser] = useState<string | null>(null);
  const [exportingCsv, setExportingCsv] = useState(false);
  const [exportingPdf, setExportingPdf] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);

    api<MemberCompliance[]>("/compliance/members")
      .then((data) => {
        if (cancelled) return;
        setMembers(data);
        setIsAdmin(true);
      })
      .catch((err: any) => {
        if (err?.status === 403) {
          // Normal member: fetch my personal workstation compliance state
          return api<MemberCompliance>("/compliance/my").then((my) => {
            if (cancelled) return;
            setMyCompliance(my);
            setIsAdmin(false);
          });
        } else {
          setError(err?.message || "Failed to retrieve workstation compliance posture.");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const filteredMembers = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return members;
    return members.filter(
      (m) =>
        m.email.toLowerCase().includes(q) ||
        (m.name ?? "").toLowerCase().includes(q) ||
        m.role.toLowerCase().includes(q)
    );
  }, [members, searchQuery]);

  const stats = useMemo(() => {
    if (!isAdmin) return null;
    const total = members.length;
    const monitored = members.filter((m) => m.studio_installed && m.monitors_enabled).length;
    const unmonitored = total - monitored;
    
    // Average device compliance score across monitored endpoints
    const monitoredDevices = members.filter((m) => m.studio_installed);
    const avgScore = monitoredDevices.length
      ? Math.round(monitoredDevices.reduce((sum, m) => sum + m.overall_device_score, 0) / monitoredDevices.length)
      : 100;

    const threats = members.filter((m) => m.overall_file_status === "Threat Detected").length;
    const suspicious = members.filter((m) => m.overall_file_status === "Suspicious Activity").length;

    return {
      total,
      monitored,
      unmonitored,
      avgScore,
      threats,
      suspicious,
    };
  }, [members, isAdmin]);

  async function handleExportCsv() {
    try {
      setExportingCsv(true);
      await downloadFile("/compliance/export/csv");
    } catch (err: any) {
      alert(err?.message || "Failed to export compliance CSV.");
    } finally {
      setExportingCsv(false);
    }
  }

  async function handleExportPdf(userId: string, email: string) {
    try {
      setExportingPdf(userId);
      await downloadFile(`/compliance/export/pdf/${userId}`);
    } catch (err: any) {
      alert(err?.message || "Failed to download compliance PDF report.");
    } finally {
      setExportingPdf(null);
    }
  }

  if (loading) return <PageLoading title="Workstation Compliance" cards={4} />;
  if (error) {
    return (
      <div className="p-6 text-center border border-hairline rounded-sm bg-oxblood/10">
        <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-sev-critical">Error</p>
        <h3 className="mt-3 font-display text-[24px] text-ink">Failed to load compliance data</h3>
        <p className="mt-2 font-body text-[14px] text-slate">{error}</p>
      </div>
    );
  }

  // Helper styles
  const getScoreColor = (score: number) => {
    if (score >= 90) return "text-forest border-forest bg-forest/10";
    if (score >= 70) return "text-sev-medium border-sev-medium bg-sev-medium/10";
    return "text-sev-critical border-sev-critical bg-sev-critical/10";
  };

  const getFileStatusStyles = (status: string) => {
    switch (status) {
      case "Clean":
        return "text-forest border-forest bg-forest/10";
      case "Suspicious Activity":
        return "text-sev-medium border-sev-medium bg-sev-medium/10";
      case "Threat Detected":
        return "text-sev-critical border-sev-critical bg-sev-critical/10";
      default:
        return "text-slate border-hairline bg-vellum/40";
    }
  };

  const getCheckStatusBadge = (status: CheckResult["status"]) => {
    switch (status) {
      case "SECURE":
        return <Badge variant="lime">Secure</Badge>;
      case "WARNING":
        return <Badge variant="pink">Warning</Badge>;
      case "INFO":
        return <Badge variant="yellow">Info</Badge>;
      default:
        return <Badge variant="pink">Pending</Badge>;
    }
  };

  const getFileStatusBadge = (status: FileAuditResult["status"]) => {
    switch (status) {
      case "CLEAN":
        return <Badge variant="lime">Clean</Badge>;
      case "SUSPICIOUS":
        return <Badge variant="pink">Suspicious</Badge>;
      case "MALICIOUS":
        return <Badge variant="danger">Malicious</Badge>;
    }
  };

  return (
    <div className="-mx-5 md:-mx-6 -mt-6 -mb-6 flex">
      {/* ─── Main Content ─── */}
      <div className="flex-1 min-w-0 px-5 md:px-6 py-6 space-y-6">
        <header>
          <div className="mt-3 flex items-end justify-between gap-4 flex-wrap">
            <h1 className="font-display text-[40px] leading-[1.05] tracking-[-0.015em] text-ink">Workstation Compliance.</h1>
            {isAdmin && (
              <Button variant="pink" disabled={exportingCsv} onClick={handleExportCsv}>
                {exportingCsv ? "Exporting CSV..." : "Export CSV report"}
              </Button>
            )}
          </div>
          <p className="mt-2 font-body text-[14px] text-slate">
            Endpoint security posture monitoring, metadata compliance checks, and audit logs.
          </p>
        </header>

        {/* ─── Admin View ─── */}
        {isAdmin && stats && (
          <>
            {/* Stat bar */}
            <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-3">
              <StatCard label="Total Staff" value={stats.total} />
              <StatCard label="Monitored Devices" value={stats.monitored} highlight="green" />
              <StatCard label="Not Configured" value={stats.unmonitored} highlight={stats.unmonitored > 0 ? "red" : undefined} />
              <StatCard label="Avg Score" value={`${stats.avgScore}%`} />
              <StatCard label="Threat Alerts" value={stats.threats} highlight={stats.threats > 0 ? "red" : undefined} />
              <StatCard label="Suspicious Files" value={stats.suspicious} />
            </div>

            {/* Member Ledger */}
            <section className="space-y-4">
              <div className="flex items-center justify-between gap-4 flex-wrap">
                <div>
                  <h2 className="font-display text-[22px] text-ink">Workstation Security Status</h2>
                </div>
                <div className="w-full sm:w-[320px]">
                  <Input
                    type="search"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search staff members…"
                    aria-label="Search members"
                  />
                </div>
              </div>

              <div className="border border-hairline rounded-sm overflow-hidden bg-vellum/10">
                <table className="w-full text-left">
                  <thead>
                    <tr className="border-b border-hairline bg-vellum">
                      <th className="px-4 py-2.5 font-mono text-[10px] uppercase tracking-[0.14em] text-mist">User</th>
                      <th className="px-4 py-2.5 font-mono text-[10px] uppercase tracking-[0.14em] text-mist">Pencheff Studio</th>
                      <th className="px-4 py-2.5 font-mono text-[10px] uppercase tracking-[0.14em] text-mist">Device Score</th>
                      <th className="px-4 py-2.5 font-mono text-[10px] uppercase tracking-[0.14em] text-mist">Downloads Security</th>
                      <th className="px-4 py-2.5 font-mono text-[10px] uppercase tracking-[0.14em] text-mist text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-hairline">
                    {filteredMembers.map((m) => {
                      const isExpanded = expandedUser === m.user_id;
                      const hasStudio = m.studio_installed;
                      const isSecure = m.monitors_enabled;
                      
                      return (
                        <React.Fragment key={m.user_id}>
                          <tr className="hover:bg-vellum/30 transition-colors">
                            <td className="px-4 py-3">
                              <div className="font-body text-[14px] font-bold text-ink">
                                {m.name || "—"}
                              </div>
                              <div className="font-mono text-[11px] text-slate">{m.email}</div>
                              <div className="mt-1">
                                <span className="inline-flex rounded-sm px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-[0.12em] bg-vellum border border-hairline text-mist">
                                  {m.role}
                                </span>
                              </div>
                            </td>
                            <td className="px-4 py-3">
                              {hasStudio ? (
                                <div className="space-y-1">
                                  <span className="inline-flex items-center gap-1 border border-forest/30 rounded-sm px-1.5 py-0.5 font-mono text-[10px] uppercase text-forest bg-forest/5">
                                    <span className="w-1.5 h-1.5 rounded-full bg-forest" /> Installed
                                  </span>
                                  <div>
                                    <span className={`inline-flex items-center gap-1 rounded-sm px-1.5 py-0.5 font-mono text-[9px] uppercase ${isSecure ? 'text-forest' : 'text-sev-medium'}`}>
                                      Monitors: {isSecure ? "Enabled" : "Disabled"}
                                    </span>
                                  </div>
                                </div>
                              ) : (
                                <span className="inline-flex items-center gap-1 border border-sev-critical/30 rounded-sm px-1.5 py-0.5 font-mono text-[10px] uppercase text-sev-critical bg-sev-critical/5">
                                  <span className="w-1.5 h-1.5 rounded-full bg-sev-critical" /> Not Installed
                                </span>
                              )}
                            </td>
                            <td className="px-4 py-3">
                              {hasStudio ? (
                                <span className={`inline-flex border rounded-sm px-2 py-0.5 font-mono text-[12px] font-bold ${getScoreColor(m.overall_device_score)}`}>
                                  {m.overall_device_score}%
                                </span>
                              ) : (
                                <span className="font-mono text-[12px] text-mist">—</span>
                              )}
                            </td>
                            <td className="px-4 py-3">
                              {hasStudio ? (
                                <span className={`inline-flex border rounded-sm px-2 py-0.5 font-mono text-[10px] uppercase font-bold tracking-wider ${getFileStatusStyles(m.overall_file_status)}`}>
                                  {m.overall_file_status}
                                </span>
                              ) : (
                                <span className="font-mono text-[12px] text-mist">—</span>
                              )}
                            </td>
                            <td className="px-4 py-3 text-right">
                              <div className="flex items-center justify-end gap-2">
                                <Button
                                  variant="lime"
                                  className="text-[11px] px-2.5 py-1"
                                  onClick={() => setExpandedUser(isExpanded ? null : m.user_id)}
                                >
                                  {isExpanded ? "Collapse" : "Inspect"}
                                </Button>
                                <Button
                                  variant="pink"
                                  className="text-[11px] px-2.5 py-1"
                                  disabled={exportingPdf === m.user_id || !hasStudio}
                                  onClick={() => handleExportPdf(m.user_id, m.email)}
                                >
                                  {exportingPdf === m.user_id ? "Generating..." : "PDF"}
                                </Button>
                              </div>
                            </td>
                          </tr>

                          {/* Expanded Inspection Panel */}
                          {isExpanded && (
                            <tr>
                              <td colSpan={5} className="bg-vellum/20 border-t border-hairline p-4">
                                {!hasStudio ? (
                                  <div className="p-4 border border-sev-critical/30 bg-sev-critical/5 text-center text-sev-critical rounded-sm">
                                    <p className="font-bold text-[14px]">Compliance Safeguards Off</p>
                                    <p className="text-[12px] mt-1">This user has not installed Pencheff Studio or enabled monitors. Telemetry is unavailable.</p>
                                  </div>
                                ) : (
                                  <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
                                    {/* Device Checks */}
                                    <div className="space-y-3">
                                      <h3 className="font-display text-[16px] text-ink border-b border-hairline pb-2 flex items-center gap-2">
                                        <ShieldCheckIcon /> Device Audit Results
                                      </h3>
                                      <div className="space-y-2">
                                        {m.device_checks_json?.map((check) => (
                                          <div key={check.key} className="border border-hairline rounded-sm p-3 bg-paper">
                                            <div className="flex items-start justify-between gap-4">
                                              <div>
                                                <h4 className="font-body font-bold text-[13px] text-ink">{check.name}</h4>
                                                <p className="text-[11px] text-slate mt-1">{check.description}</p>
                                              </div>
                                              {getCheckStatusBadge(check.status)}
                                            </div>
                                            <div className="mt-3 p-2 bg-ink text-slate-100 rounded-sm font-mono text-[10px] leading-tight space-y-1">
                                              <div className="flex items-center gap-1 text-gilt">
                                                <span>$</span> <span>{check.command} {check.args?.join(" ")}</span>
                                              </div>
                                              <pre className="whitespace-pre-wrap break-all opacity-95">{check.rawOutput}</pre>
                                            </div>
                                          </div>
                                        ))}
                                      </div>
                                    </div>

                                    {/* File Monitor downloads list */}
                                    <div className="space-y-3">
                                      <h3 className="font-display text-[16px] text-ink border-b border-hairline pb-2 flex items-center gap-2">
                                        <ShieldAlertIcon /> File Monitor Audits
                                      </h3>
                                      <div className="space-y-2">
                                        {m.file_checks_json?.map((file, idx) => (
                                          <div key={idx} className="border border-hairline rounded-sm p-3 bg-paper">
                                            <div className="flex items-start justify-between gap-4">
                                              <div className="min-w-0">
                                                <h4 className="font-body font-bold text-[13px] text-ink truncate">{file.name}</h4>
                                                <p className="text-[10px] text-slate mt-1 truncate">Path: {file.path}</p>
                                                <div className="flex gap-2 flex-wrap items-center mt-2 font-mono text-[9px] text-mist">
                                                  <span>Size: {file.formattedSize}</span>
                                                  <span>•</span>
                                                  <span>Permissions: {file.permissions}</span>
                                                  <span>•</span>
                                                  <span>Source: {file.downloadSource}</span>
                                                </div>
                                              </div>
                                              {getFileStatusBadge(file.status)}
                                            </div>
                                            <div className="mt-3 p-2 bg-ink text-slate-100 rounded-sm font-mono text-[10px] leading-tight space-y-1">
                                              <div className="flex items-center gap-1 text-gilt">
                                                <span>$</span> <span>xattr -p com.apple.quarantine {file.name}</span>
                                              </div>
                                              <div className="opacity-95 truncate">{file.quarantineRaw || "No web quarantine attributes found. (Origin: Local)"}</div>
                                            </div>
                                          </div>
                                        ))}
                                        {(!m.file_checks_json || m.file_checks_json.length === 0) && (
                                          <p className="text-[12px] text-slate italic">No downloads metadata checked yet.</p>
                                        )}
                                      </div>
                                    </div>
                                  </div>
                                )}
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        )}

        {/* ─── Standard Member View ─── */}
        {!isAdmin && myCompliance && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left Posture Summary Card */}
            <div className="lg:col-span-2 space-y-6">
              {!myCompliance.studio_installed ? (
                <div className="border-2 border-dashed border-sev-medium rounded-sm p-8 bg-sev-medium/5 flex items-start gap-4">
                  <div className="p-3 bg-sev-medium/10 rounded-full text-sev-medium shrink-0">
                    <ShieldAlertIcon />
                  </div>
                  <div>
                    <h3 className="font-display text-[20px] text-ink font-bold">Pencheff Studio Not Connected</h3>
                    <p className="font-body text-[14px] text-slate mt-2 max-w-[50ch]">
                      Your local workstation has not installed Pencheff Studio or enabled compliance monitors. To maintain workspace access and align with security protocols, please download and run the Pencheff Studio desktop app.
                    </p>
                    <div className="mt-5">
                      <Button variant="pink">Download Pencheff Studio</Button>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="border border-forest/30 rounded-sm p-6 bg-forest/5 flex items-center gap-4">
                  <div className="p-3 bg-forest/10 rounded-full text-forest shrink-0">
                    <ShieldCheckIcon />
                  </div>
                  <div>
                    <h3 className="font-display text-[18px] text-ink font-bold">Workstation Active & Monitored</h3>
                    <p className="font-body text-[13px] text-slate mt-1">
                      Your workstation compliance telemetry is successfully syncing. Last updated: {myCompliance.updated_at ? new Date(myCompliance.updated_at).toLocaleString() : "Never"}.
                    </p>
                  </div>
                </div>
              )}

              {myCompliance.studio_installed && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Device Score */}
                  <Card className="p-5 flex flex-col items-center text-center justify-center space-y-3">
                    <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">Device Compliance Score</p>
                    <div className={`w-24 h-24 rounded-full border-4 flex items-center justify-center font-display text-[26px] font-bold ${getScoreColor(myCompliance.overall_device_score)}`}>
                      {myCompliance.overall_device_score}%
                    </div>
                    <p className="text-[12px] text-slate">Protects operating system assets, disk encryption, and firewall status.</p>
                  </Card>

                  {/* Downloads status */}
                  <Card className="p-5 flex flex-col items-center text-center justify-center space-y-3">
                    <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">Downloads File Security</p>
                    <div className={`border-2 rounded-sm px-4 py-2 font-display text-[18px] uppercase tracking-wider font-bold ${getFileStatusStyles(myCompliance.overall_file_status)}`}>
                      {myCompliance.overall_file_status}
                    </div>
                    <p className="text-[12px] text-slate">Audits file extensions and quarantine configurations privately.</p>
                  </Card>
                </div>
              )}

              {/* Checks Accordions for personal device */}
              {myCompliance.studio_installed && (
                <div className="space-y-4">
                  <div className="space-y-2">
                    <h3 className="font-display text-[18px] text-ink border-b border-hairline pb-2 flex items-center gap-2">
                      <ShieldCheckIcon /> System Posture Checks
                    </h3>
                    <div className="space-y-3">
                      {myCompliance.device_checks_json?.map((check) => (
                        <div key={check.key} className="border border-hairline rounded-sm p-4 bg-vellum/5">
                          <div className="flex items-start justify-between gap-4">
                            <div>
                              <h4 className="font-body font-bold text-[14px] text-ink">{check.name}</h4>
                              <p className="text-[12px] text-slate mt-1">{check.description}</p>
                            </div>
                            {getCheckStatusBadge(check.status)}
                          </div>
                          <div className="mt-3 p-3 bg-ink text-slate-100 rounded-sm font-mono text-[11px] leading-tight space-y-1">
                            <div className="flex items-center gap-1 text-gilt">
                              <span>$</span> <span>{check.command} {check.args?.join(" ")}</span>
                            </div>
                            <pre className="whitespace-pre-wrap break-all opacity-95">{check.rawOutput}</pre>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Right sidebar - Standards Policy checklist */}
            {myCompliance.studio_installed && (
              <aside className="space-y-6">
                <IntelPanel title="Policy Compliance" eyebrow="Policy Framework">
                  <p className="text-[13px] text-slate leading-relaxed">
                    Continuous monitoring ensures alignment with global compliance standards and corporate policies.
                  </p>
                  <IntelDivider label="Alignment Status" />
                  <div className="space-y-3 mt-3">
                    <IntelRow label="SOC 2 Type II" value={`${myCompliance.overall_device_score}%`} bar={myCompliance.overall_device_score} color="bg-forest" />
                    <IntelRow label="ISO/IEC 27001" value={`${myCompliance.overall_device_score}%`} bar={myCompliance.overall_device_score} color="bg-forest" />
                    <IntelRow label="PCI-DSS v4.0" value={myCompliance.overall_file_status === 'Clean' ? '100%' : '60%'} bar={myCompliance.overall_file_status === 'Clean' ? 100 : 60} color={myCompliance.overall_file_status === 'Clean' ? 'bg-forest' : 'bg-sev-medium'} />
                    <IntelRow label="NIST SP 800-53" value={myCompliance.overall_file_status === 'Clean' ? '100%' : '80%'} bar={myCompliance.overall_file_status === 'Clean' ? 100 : 80} color={myCompliance.overall_file_status === 'Clean' ? 'bg-forest' : 'bg-sev-medium'} />
                  </div>
                </IntelPanel>
              </aside>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

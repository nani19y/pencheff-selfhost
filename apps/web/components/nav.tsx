"use client";

import { useEffect, useRef, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import Link from "next/link";
import { Button, Input } from "@/components/brutal";
import { LogoMark } from "@/components/logo";
import { ThemeToggle } from "@/components/theme-toggle";
import { cn } from "@/lib/cn";
import {
  ACTIVE_ORG_STORAGE_KEY,
  ACTIVE_WORKSPACE_STORAGE_KEY,
  ApiError,
  api,
} from "@/lib/api";
import { useWorkspace } from "@/lib/workspace-context";
import {
  useNotifications,
  type AppNotification,
} from "@/lib/notifications-context";

const DOCS_URL =
  process.env.NEXT_PUBLIC_DOCS_URL ?? "https://docs.pencheff.com";

// ─── Nav icons ──────────────────────────────────────────────────────────────

function DashboardIcon() {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden
    >
      <rect x="1.5" y="1.5" width="5" height="5" rx="0.5" />
      <rect x="9.5" y="1.5" width="5" height="5" rx="0.5" />
      <rect x="1.5" y="9.5" width="5" height="5" rx="0.5" />
      <rect x="9.5" y="9.5" width="5" height="5" rx="0.5" />
    </svg>
  );
}
function TargetsIcon() {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden
    >
      <circle cx="8" cy="8" r="6.5" />
      <circle cx="8" cy="8" r="3" />
      <circle cx="8" cy="8" r="0.75" fill="currentColor" stroke="none" />
    </svg>
  );
}
function RegisterTargetIcon() {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      aria-hidden
    >
      <path d="M8 2v12M2 8h12" />
    </svg>
  );
}
function FindingsIcon() {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden
    >
      <circle cx="7" cy="7" r="5" />
      <path d="M11 11l3.5 3.5" />
    </svg>
  );
}
function AssessmentsIcon() {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden
    >
      <rect x="3" y="1.5" width="10" height="13" rx="0.5" />
      <path d="M5.5 6l1.5 1.5L10.5 5M5.5 10.5h5" />
    </svg>
  );
}
function SchedulesIcon() {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden
    >
      <circle cx="8" cy="8" r="6.5" />
      <path d="M8 4.5V8l2.5 2.5" />
    </svg>
  );
}
function ReportsIcon() {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden
    >
      <rect x="2.5" y="1.5" width="11" height="13" rx="0.5" />
      <path d="M5 5.5h6M5 8h6M5 10.5h4" />
    </svg>
  );
}
function AsmIcon() {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden
    >
      <circle cx="8" cy="8" r="2" />
      <circle cx="2.5" cy="4" r="1.5" />
      <circle cx="13.5" cy="4" r="1.5" />
      <circle cx="2.5" cy="12" r="1.5" />
      <circle cx="13.5" cy="12" r="1.5" />
      <path d="M4 4.5l2.5 2.5M9.5 9l2.5 2.5M4 11.5l2.5-2.5M9.5 7 12 4.5" />
    </svg>
  );
}
function IntegrationsIcon() {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden
    >
      <rect x="1.5" y="5.5" width="5" height="5" rx="0.5" />
      <rect x="9.5" y="5.5" width="5" height="5" rx="0.5" />
      <path d="M6.5 8h3" strokeDasharray="1 1" />
    </svg>
  );
}
function SettingsIcon() {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden
    >
      <circle cx="8" cy="8" r="2.5" />
      <path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.6 3.6l1.4 1.4M11 11l1.4 1.4M3.6 12.4l1.4-1.4M11 5l1.4-1.4" />
    </svg>
  );
}
function ShieldIcon() {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden
    >
      <path d="M8 1.5L2 4.5v4c0 3.5 2.5 5.5 6 6.5 3.5-1 6-3 6-6.5v-4L8 1.5z" />
    </svg>
  );
}
function BellIcon() {
  return (
    <svg
      viewBox="0 0 20 20"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden
    >
      <path d="M10 2a6 6 0 0 1 6 6v3l1.5 2.5h-15L4 11V8a6 6 0 0 1 6-6z" />
      <path d="M8 17a2 2 0 0 0 4 0" />
    </svg>
  );
}

// ─── Nav configuration ───────────────────────────────────────────────────────

const PRIMARY_NAV = [
  { href: "/dashboard", label: "Dashboard", icon: <DashboardIcon /> },
  { href: "/targets", label: "Targets", icon: <TargetsIcon /> },
  {
    href: "/targets/new",
    label: "Register Target",
    icon: <RegisterTargetIcon />,
  },
  { href: "/findings", label: "Findings", icon: <FindingsIcon /> },
  { href: "/scans", label: "Assessments", icon: <AssessmentsIcon /> },
  { href: "/schedules", label: "Schedules", icon: <SchedulesIcon /> },
] as const;

const SETTINGS_NAV = [
  { href: "/integrations", label: "Integrations", icon: <IntegrationsIcon /> },
  { href: "/settings", label: "Settings", icon: <SettingsIcon /> },
] as const;

// WORKBENCH_ITEMS kept for mobile menu compatibility
const WORKBENCH_ITEMS: { href: string; label: string }[] = [
  { href: "/targets", label: "Targets" },
  { href: "/targets/new", label: "Register Target" },
  { href: "/findings", label: "Findings" },
  { href: "/scans", label: "Assessments" },
  { href: "/schedules", label: "Schedules" },
];

// ─── Shared helpers ──────────────────────────────────────────────────────────

function switchWorkspace(orgId: string | null, workspaceId: string | null) {
  try {
    if (orgId) window.localStorage.setItem(ACTIVE_ORG_STORAGE_KEY, orgId);
    if (workspaceId)
      window.localStorage.setItem(ACTIVE_WORKSPACE_STORAGE_KEY, workspaceId);
  } catch {
    /* swallow */
  }
  const path = window.location.pathname;
  const detailRoot =
    /^\/(scans|targets|findings|sbom|dependencies|repos)\/[^/]+/;
  if (detailRoot.test(path)) window.location.href = "/dashboard";
  else window.location.reload();
}

function _isActiveRoute(pathname: string, href: string): boolean {
  if (href === "/dashboard") return pathname === "/dashboard";
  if (href === "/") return pathname === "/";
  return pathname === href || pathname.startsWith(href + "/");
}

// ─── Dropdown ────────────────────────────────────────────────────────────────

function SwitchDropdown({
  ariaLabel,
  value,
  options,
  stacked,
  maxWidth,
  onChange,
  dark,
}: {
  ariaLabel: string;
  value: string;
  options: { value: string; label: string }[];
  stacked: boolean;
  maxWidth: string;
  onChange: (value: string) => void;
  dark?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const selected = options.find((o) => o.value === value)?.label ?? "";
  return (
    <div className={`relative ${stacked ? "w-full" : `${maxWidth} min-w-0`}`}>
      <button
        type="button"
        aria-label={ariaLabel}
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className={cn(
          "w-full flex items-center justify-between gap-2 min-w-0 rounded-sm px-2 py-1.5 font-body text-[12px] leading-none focus:outline-none",
          dark
            ? "bg-white/[0.08] border border-white/20 text-white/80 hover:border-white/40"
            : "bg-vellum border border-hairline text-graphite hover:border-ink",
        )}
      >
        <span className="truncate">{selected}</span>
        <span
          className={cn(
            "text-[10px] shrink-0",
            dark ? "text-white/40" : "text-mist",
          )}
          aria-hidden
        >
          ▾
        </span>
      </button>
      {open && (
        <div
          className={cn(
            "absolute left-0 right-0 mt-1 rounded-sm shadow-subtle overflow-hidden z-50 border",
            dark ? "bg-graphite border-white/10" : "bg-paper border-hairline",
          )}
          onMouseLeave={() => setOpen(false)}
        >
          {options.map((o) => {
            const active = o.value === value;
            return (
              <button
                key={o.value}
                type="button"
                className={cn(
                  "w-full text-left px-2.5 py-2 text-[13px]",
                  dark
                    ? active
                      ? "bg-white/10 text-paper"
                      : "text-white/70 hover:bg-white/5 hover:text-paper"
                    : active
                      ? "bg-ink text-paper"
                      : "text-graphite hover:bg-vellum hover:text-ink",
                )}
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => {
                  setOpen(false);
                  onChange(o.value);
                }}
              >
                <div className="flex items-center justify-between gap-3">
                  <span className="truncate">{o.label}</span>
                  {active && (
                    <span className="text-[11px] opacity-90" aria-hidden>
                      ✓
                    </span>
                  )}
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function WorkspaceSwitcherControls({
  stacked = false,
  dark = false,
}: {
  stacked?: boolean;
  dark?: boolean;
}) {
  const { orgs, activeOrg, workspaces, activeWorkspace } = useWorkspace();
  if (orgs.length === 0) return null;

  const orgOptions = orgs.map((o) => ({ value: o.id, label: o.name }));
  const orgValue = activeOrg?.id ?? orgOptions[0]?.value ?? "";
  const orgSelect = (
    <SwitchDropdown
      ariaLabel="Organisation"
      value={orgValue}
      options={orgOptions}
      stacked={stacked}
      maxWidth="max-w-[150px]"
      dark={dark}
      onChange={(orgId) => {
        const firstInOrg =
          workspaces.find((w) => w.org_id === orgId)?.id ?? null;
        switchWorkspace(orgId, firstInOrg);
      }}
    />
  );

  const wsOptions = workspaces.map((w) => ({ value: w.id, label: w.name }));
  const wsValue = activeWorkspace?.id ?? workspaces[0]?.id ?? "";
  const wsSelect = (
    <SwitchDropdown
      ariaLabel="Workspace"
      value={wsValue}
      options={wsOptions}
      stacked={stacked}
      maxWidth="max-w-[160px]"
      dark={dark}
      onChange={(v) => {
        switchWorkspace(activeOrg?.id ?? null, v);
      }}
    />
  );

  if (stacked) {
    return (
      <div className="flex flex-col gap-2">
        <label
          className={cn(
            "text-[10px] uppercase tracking-[0.14em] px-0.5",
            dark ? "text-white/40" : "text-mist",
          )}
        >
          Organisation
        </label>
        {orgSelect}
        <label
          className={cn(
            "text-[10px] uppercase tracking-[0.14em] px-0.5 mt-1",
            dark ? "text-white/40" : "text-mist",
          )}
        >
          Workspace
        </label>
        {wsSelect}
      </div>
    );
  }
  return (
    <div className="flex items-center gap-1.5 min-w-0">
      {orgSelect}
      <span className="text-mist text-[11px] select-none">/</span>
      {wsSelect}
    </div>
  );
}

// ─── Sidebar link ────────────────────────────────────────────────────────────

function SidebarLink({
  href,
  label,
  icon,
  pathname,
  collapsed,
}: {
  href: string;
  label: string;
  icon?: React.ReactNode;
  pathname: string;
  collapsed?: boolean;
}) {
  const active = _isActiveRoute(pathname, href);
  return (
    <Link
      href={href}
      data-tooltip={collapsed ? label : undefined}
      aria-label={collapsed ? label : undefined}
      className={cn(
        "sidebar-link relative flex items-center rounded-sm transition-colors duration-150",
        "font-body text-[13px] font-medium tracking-[0.02em]",
        "border-l-2 -ml-[2px]",
        collapsed
          ? "justify-center px-2 py-2 pl-2"
          : "gap-2.5 px-3 py-2 pl-[14px]",
        active
          ? "text-ink bg-vellum border-gilt"
          : "text-slate hover:bg-vellum hover:text-ink border-transparent",
      )}
      aria-current={active ? "page" : undefined}
    >
      {icon && (
        <span
          className={cn("w-4 h-4 shrink-0", active ? "text-gilt" : "text-mist")}
        >
          {icon}
        </span>
      )}
      {!collapsed && <span className="truncate">{label}</span>}
    </Link>
  );
}

// ─── Mobile hamburger ─────────────────────────────────────────────────────────

function HamburgerIcon({ open }: { open: boolean }) {
  return (
    <span
      aria-hidden
      className="relative inline-flex items-center justify-center w-5 h-5"
    >
      <span
        className={`absolute left-0 right-0 h-px bg-ink transition-transform ${open ? "rotate-45 top-[9px]" : "top-[5px]"}`}
      />
      <span
        className={`absolute left-0 right-0 h-px bg-ink transition-opacity ${open ? "opacity-0" : "top-[9px] opacity-100"}`}
      />
      <span
        className={`absolute left-0 right-0 h-px bg-ink transition-transform ${open ? "-rotate-45 top-[9px]" : "top-[13px]"}`}
      />
    </span>
  );
}

function NavLink({
  href,
  children,
  className,
  onClick,
}: {
  href: string;
  children: React.ReactNode;
  className?: string;
  onClick?: () => void;
}) {
  return (
    <Link
      href={href}
      onClick={onClick}
      className={
        "font-body text-[13px] font-medium tracking-[0.04em] text-slate " +
        "hover:text-ink underline-offset-[6px] hover:underline decoration-gilt decoration-1 " +
        "transition-colors duration-150 " +
        (className ?? "")
      }
    >
      {children}
    </Link>
  );
}

function DocsLink({ className }: { className?: string }) {
  return (
    <a
      href={DOCS_URL}
      target="_blank"
      rel="noreferrer"
      className={
        "font-body text-[13px] font-medium tracking-[0.04em] text-slate " +
        "hover:text-ink underline-offset-[6px] hover:underline decoration-gilt decoration-1 " +
        "transition-colors duration-150 " +
        (className ?? "")
      }
    >
      Docs ↗
    </a>
  );
}

function Monogram({ href }: { href: string }) {
  return (
    <Link
      href={href}
      className="inline-flex items-center gap-2.5 text-ink"
      aria-label="Pencheff (beta)"
    >
      <LogoMark size={36} priority className="shrink-0" />
      <span className="font-display text-[20px] font-medium tracking-[0.02em]">
        Pencheff
      </span>
      <BetaBadge />
    </Link>
  );
}

function MonogramDark({ href }: { href: string }) {
  return (
    <Link
      href={href}
      className="inline-flex items-center gap-2.5 text-paper"
      aria-label="Pencheff (beta)"
    >
      <LogoMark size={36} priority className="shrink-0 invert" />
      <span className="font-display text-[20px] font-medium tracking-[0.02em]">
        Pencheff
      </span>
      <BetaBadge />
    </Link>
  );
}

function BetaBadge() {
  return (
    <span
      className="inline-flex items-center gap-1 border border-gilt rounded-sm px-1.5 py-0.5 font-mono text-[10px] font-medium uppercase tracking-[0.18em] text-gilt bg-vellum whitespace-nowrap"
      aria-label="Pencheff is in open beta"
    >
      Beta
    </span>
  );
}

function relativeNotificationTime(ts: number): string {
  const diff = Date.now() - ts;
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(diff / 3_600_000);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(diff / 86_400_000);
  if (days < 7) return `${days}d ago`;
  return new Date(ts).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
  });
}

function NotificationBell() {
  const router = useRouter();
  const {
    notifications,
    unreadCount,
    permission,
    requestPermission,
    markAllRead,
    remove,
    clear,
  } = useNotifications();
  const [open, setOpen] = useState(false);
  const wrapperRef = useRef<HTMLDivElement | null>(null);

  // Close on outside click.
  useEffect(() => {
    if (!open) return;
    function onDown(e: MouseEvent) {
      if (
        wrapperRef.current &&
        !wrapperRef.current.contains(e.target as Node)
      ) {
        setOpen(false);
      }
    }
    window.addEventListener("mousedown", onDown);
    return () => window.removeEventListener("mousedown", onDown);
  }, [open]);

  function openItem(n: AppNotification) {
    setOpen(false);
    if (!n.read) {
      // optimistic mark-read isn't needed — markAllRead on open does it
    }
    if (n.href) router.push(n.href);
  }

  return (
    <div ref={wrapperRef} className="relative">
      <button
        type="button"
        aria-label={`Notifications${unreadCount > 0 ? ` (${unreadCount} unread)` : ""}`}
        onClick={() => {
          setOpen((v) => {
            const next = !v;
            if (next && unreadCount > 0) markAllRead();
            return next;
          });
        }}
        className="relative p-1.5 rounded-sm hover:bg-vellum transition-colors"
      >
        <span className="w-5 h-5 text-slate block">
          <BellIcon />
        </span>
        {unreadCount > 0 && (
          <span className="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 bg-gilt text-ink text-[9px] font-mono font-bold rounded-full flex items-center justify-center px-1">
            {unreadCount > 99 ? "99+" : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-1 w-[340px] max-h-[480px] bg-paper border border-hairline rounded-sm shadow-elev z-50 flex flex-col overflow-hidden">
          <div className="px-4 py-3 border-b border-hairline flex items-center justify-between gap-2">
            <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">
              Notifications
            </p>
            {notifications.length > 0 && (
              <button
                type="button"
                onClick={clear}
                className="font-mono text-[10px] uppercase tracking-[0.14em] text-mist hover:text-ink transition-colors"
              >
                Clear all
              </button>
            )}
          </div>

          {/* Browser-push permission prompt */}
          {permission === "default" && (
            <div className="px-4 py-3 border-b border-hairline bg-vellum/40">
              <p className="font-body text-[12px] text-graphite">
                Get notified outside this tab when assessments finish or
                findings are assigned to you.
              </p>
              <button
                type="button"
                onClick={requestPermission}
                className="mt-2 inline-flex items-center gap-1.5 bg-ink text-paper rounded-sm px-3 py-1.5 font-body text-[12px] hover:bg-graphite transition-colors"
              >
                Enable browser notifications
              </button>
            </div>
          )}
          {permission === "denied" && (
            <div className="px-4 py-2 border-b border-hairline bg-sev-high/5">
              <p className="font-body text-[11px] text-slate">
                Browser notifications are blocked. Update your site permissions
                to re-enable.
              </p>
            </div>
          )}

          {/* List */}
          {notifications.length === 0 ? (
            <div className="px-4 py-8 text-center">
              <p className="font-body text-[13px] text-mist italic">
                No notifications yet.
              </p>
              <p className="font-mono text-[10px] text-mist mt-1">
                Assessment results and assignments will appear here.
              </p>
            </div>
          ) : (
            <ul className="flex-1 overflow-y-auto divide-y divide-hairline">
              {notifications.map((n) => (
                <li
                  key={n.id}
                  className={cn(
                    "group/notification",
                    !n.read && "bg-vellum/30",
                  )}
                >
                  <div className="px-4 py-3 flex items-start gap-2.5">
                    <span
                      className={cn(
                        "w-1.5 h-1.5 rounded-full shrink-0 mt-1.5",
                        n.kind === "assessment-failed"
                          ? "bg-sev-critical"
                          : n.kind === "assessment-done"
                            ? "bg-forest"
                            : n.kind === "assignment"
                              ? "bg-gilt"
                              : "bg-mist",
                      )}
                      aria-hidden
                    />
                    <button
                      type="button"
                      onClick={() => openItem(n)}
                      className="flex-1 text-left min-w-0"
                    >
                      <p className="font-body text-[13px] font-medium text-ink">
                        {n.title}
                      </p>
                      {n.body && (
                        <p className="font-body text-[12px] text-slate mt-0.5 line-clamp-2">
                          {n.body}
                        </p>
                      )}
                      <p className="font-mono text-[10px] text-mist mt-1">
                        {relativeNotificationTime(n.at)}
                      </p>
                    </button>
                    <button
                      type="button"
                      onClick={() => remove(n.id)}
                      aria-label="Dismiss notification"
                      className="p-1 -m-1 text-mist hover:text-graphite transition-colors opacity-0 group-hover/notification:opacity-100"
                    >
                      <svg
                        viewBox="0 0 12 12"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="1.4"
                        className="w-3 h-3"
                      >
                        <path d="M3 3l6 6M9 3l-6 6" strokeLinecap="round" />
                      </svg>
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

function WorkbenchMenu() {
  return (
    <details className="relative group hidden md:block">
      <summary className="list-none cursor-pointer inline-flex items-center gap-1 font-body text-[13px] font-medium tracking-[0.04em] text-slate hover:text-ink transition-colors duration-150 select-none">
        Workbench{" "}
        <span aria-hidden className="text-[10px] text-mist">
          ▾
        </span>
      </summary>
      <div className="absolute right-0 mt-2 w-48 bg-paper border border-hairline rounded-sm shadow-subtle z-50 py-2">
        {WORKBENCH_ITEMS.map(({ href, label }) => (
          <Link
            key={href}
            href={href}
            className="block px-4 py-1.5 text-[13px] text-graphite hover:bg-vellum hover:text-ink"
          >
            {label}
          </Link>
        ))}
      </div>
    </details>
  );
}

function MobileMenu({ open, onClose }: { open: boolean; onClose: () => void }) {
  if (!open) return null;
  return (
    <div
      id="app-mobile-menu"
      className="md:hidden border-t border-hairline bg-paper"
    >
      <div className="px-6 py-5 space-y-5">
        <WorkspaceSwitcherControls stacked />
        <div className="flex flex-col divide-y divide-hairline border-y border-hairline">
          <NavLink
            href="/dashboard"
            onClick={onClose}
            className="!text-ink !text-[15px] py-3 hover:!no-underline"
          >
            Dashboard
          </NavLink>
          {WORKBENCH_ITEMS.map(({ href, label }) => (
            <NavLink
              key={href}
              href={href}
              onClick={onClose}
              className="!text-graphite !text-[15px] py-3 hover:!no-underline"
            >
              {label}
            </NavLink>
          ))}
          <NavLink
            href="/integrations"
            onClick={onClose}
            className="!text-graphite !text-[15px] py-3 hover:!no-underline"
          >
            Integrations
          </NavLink>
          <NavLink
            href="/settings"
            onClick={onClose}
            className="!text-graphite !text-[15px] py-3 hover:!no-underline"
          >
            Settings
          </NavLink>
          <a
            href={DOCS_URL}
            target="_blank"
            rel="noreferrer"
            onClick={onClose}
            className="font-body text-[15px] text-graphite py-3"
          >
            Docs ↗
          </a>
        </div>
      </div>
    </div>
  );
}

// ─── App nav (mobile top bar) ────────────────────────────────────────────────

export function AppNav() {
  const [open, setOpen] = useState(false);
  const pathname = usePathname();

  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  return (
    <nav className="border-b border-hairline bg-paper/90 backdrop-blur sticky top-0 z-40">
      <div className="max-w-[1320px] mx-auto px-4 md:px-10 py-3 md:py-4 flex items-center justify-between gap-3 md:gap-6">
        <div className="flex items-center gap-3 md:gap-5 min-w-0">
          <Monogram href="/dashboard" />
          <div className="hidden md:block">
            <WorkspaceSwitcherControls />
          </div>
        </div>
        <div className="hidden md:flex items-center gap-5 shrink-0">
          <NavLink href="/dashboard" className="whitespace-nowrap">
            Dashboard
          </NavLink>
          <WorkbenchMenu />
          <DocsLink className="whitespace-nowrap" />
          <ThemeToggle variant="nav" />
        </div>
        <div className="flex md:hidden items-center gap-3 shrink-0">
          <ThemeToggle variant="nav" />
          <button
            type="button"
            aria-label={open ? "Close menu" : "Open menu"}
            aria-expanded={open}
            aria-controls="app-mobile-menu"
            onClick={() => setOpen((v) => !v)}
            className="inline-flex items-center justify-center w-9 h-9 border border-hairline rounded-sm bg-paper hover:border-ink transition-colors"
          >
            <HamburgerIcon open={open} />
          </button>
        </div>
      </div>
      <MobileMenu open={open} onClose={() => setOpen(false)} />
    </nav>
  );
}

// ─── App shell (desktop sidebar + header) ────────────────────────────────────

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [search, setSearch] = useState("");
  const [suggestOpen, setSuggestOpen] = useState(false);
  const [suggestLoading, setSuggestLoading] = useState(false);
  const [suggestions, setSuggestions] = useState<
    {
      label: string;
      href: string;
      meta?: string;
      group: "Targets" | "Repositories";
    }[]
  >([]);
  const searchInputRef = useRef<HTMLInputElement | null>(null);

  // Sidebar collapse state — persisted across reloads via localStorage.
  // Initial render uses `false` to avoid SSR/hydration mismatch; we read
  // the stored value in the first client-side effect.
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  useEffect(() => {
    try {
      const stored = window.localStorage.getItem("pencheff-sidebar-collapsed");
      if (stored === "1") setSidebarCollapsed(true);
    } catch {
      /* localStorage may be unavailable */
    }
  }, []);
  function toggleSidebar() {
    setSidebarCollapsed((prev) => {
      const next = !prev;
      try {
        window.localStorage.setItem(
          "pencheff-sidebar-collapsed",
          next ? "1" : "0",
        );
      } catch {
        /* ignore */
      }
      return next;
    });
  }

  // ⌘K / Ctrl+K focuses the global search. Escape clears focus + closes
  // suggestions. Skip when the user is typing in another input/textarea/
  // contenteditable so we don't steal keystrokes from forms.
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.key === "k" || e.key === "K") && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        const el = searchInputRef.current;
        if (el) {
          el.focus();
          el.select();
          setSuggestOpen(true);
        }
        return;
      }
      if (
        e.key === "Escape" &&
        searchInputRef.current === document.activeElement
      ) {
        setSuggestOpen(false);
        searchInputRef.current?.blur();
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    if (!suggestOpen) return;
    const q = search.trim();
    if (!q) {
      setSuggestions([]);
      setSuggestLoading(false);
      return;
    }
    let cancelled = false;
    const handle = window.setTimeout(() => {
      setSuggestLoading(true);
      Promise.all([
        api<
          { id: string; name: string; base_url: string; kind?: string | null }[]
        >(`/targets?q=${encodeURIComponent(q)}`).catch((e) => {
          if (e instanceof ApiError && e.status === 401) return [];
          return [];
        }),
        api<{ id: string; full_name: string; html_url: string }[]>(
          `/repos?q=${encodeURIComponent(q)}`,
        ).catch((e) => {
          if (e instanceof ApiError && e.status === 401) return [];
          return [];
        }),
      ])
        .then(([targets, repos]) => {
          if (cancelled) return;
          const next: {
            label: string;
            href: string;
            meta?: string;
            group: "Targets" | "Repositories";
          }[] = [];
          for (const t of (targets ?? []).slice(0, 6))
            next.push({
              group: "Targets",
              label: t.name,
              meta: t.base_url,
              href: `/targets/${t.id}`,
            });
          for (const r of (repos ?? []).slice(0, 6))
            next.push({
              group: "Repositories",
              label: r.full_name,
              meta: r.html_url,
              href: `/repos/${r.id}`,
            });
          setSuggestions(next.slice(0, 10));
        })
        .finally(() => !cancelled && setSuggestLoading(false));
    }, 200);
    return () => {
      cancelled = true;
      window.clearTimeout(handle);
    };
  }, [search, suggestOpen]);

  return (
    <div className="min-h-screen md:h-screen md:overflow-hidden">
      {/* Mobile: light top nav */}
      <div className="md:hidden">
        <AppNav />
        {children}
      </div>

      {/* Desktop: dark sidebar + content */}
      <div className="hidden md:flex h-screen">
        {/* ── Sidebar ── */}
        <aside
          className={cn(
            "shrink-0 h-screen overflow-y-auto border-r border-hairline bg-paper flex flex-col relative",
            "transition-[width] duration-200 ease-out",
            sidebarCollapsed ? "w-[68px]" : "w-[280px]",
          )}
          aria-label="Application sidebar"
        >
          {/* Logo + collapse toggle */}
          <div
            className={cn(
              "h-[60px] flex items-center border-b border-hairline shrink-0",
              sidebarCollapsed ? "px-2 justify-center" : "px-4 justify-between",
            )}
          >
            {!sidebarCollapsed && <Monogram href="/dashboard" />}
            <button
              type="button"
              onClick={toggleSidebar}
              aria-label={
                sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"
              }
              aria-pressed={sidebarCollapsed}
              title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
              className={cn(
                "inline-flex items-center justify-center w-8 h-8 rounded-sm",
                "border border-hairline bg-paper text-slate",
                "hover:border-ink hover:text-ink transition-colors",
              )}
            >
              <svg
                width="14"
                height="14"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.8"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden
                style={{
                  transform: sidebarCollapsed ? "rotate(180deg)" : "none",
                  transition: "transform 0.2s",
                }}
              >
                <path d="M15 18l-6-6 6-6" />
              </svg>
            </button>
          </div>

          {/* Org + Workspace (hidden when collapsed) */}
          {!sidebarCollapsed && (
            <div className="px-3 pt-4 pb-2 space-y-2 shrink-0">
              <WorkspaceSwitcherControls stacked />
            </div>
          )}

          {/* Primary nav */}
          <nav
            className={cn(
              "flex-1 py-3 space-y-0.5",
              sidebarCollapsed ? "px-2" : "px-2",
            )}
            aria-label="Primary navigation"
          >
            {PRIMARY_NAV.map((item) => (
              <SidebarLink
                key={item.href}
                href={item.href}
                label={item.label}
                icon={item.icon}
                pathname={pathname}
                collapsed={sidebarCollapsed}
              />
            ))}
          </nav>

          {/* Separator */}
          <div className="mx-3 border-t border-hairline shrink-0" />

          {/* Settings nav */}
          <nav
            className="px-2 py-3 space-y-0.5 shrink-0"
            aria-label="Settings navigation"
          >
            {SETTINGS_NAV.map((item) => (
              <SidebarLink
                key={item.href}
                href={item.href}
                label={item.label}
                icon={item.icon}
                pathname={pathname}
                collapsed={sidebarCollapsed}
              />
            ))}
          </nav>

          {/* Footer — only when expanded */}
          {!sidebarCollapsed && (
            <div className="px-4 py-3 shrink-0 border-t border-hairline">
              <p className="font-mono text-[10px] text-mist">
                © 2026 Magadha Group
              </p>
            </div>
          )}
        </aside>

        {/* ── Content area ── */}
        <div className="flex-1 min-w-0 flex flex-col">
          {/* Header */}
          <header className="h-[60px] border-b border-hairline bg-paper/90 backdrop-blur flex items-center justify-between gap-6 px-6 shrink-0">
            {/* Search */}
            <div className="flex-1 min-w-0">
              <div className="max-w-[680px] relative">
                <Input
                  ref={searchInputRef}
                  type="search"
                  value={search}
                  onChange={(e) => {
                    setSearch(e.target.value);
                    setSuggestOpen(true);
                  }}
                  placeholder="Find what you need  (⌘K)"
                  aria-label="Search"
                  className="h-9 pr-16"
                  onFocus={() => setSuggestOpen(true)}
                  onBlur={() =>
                    window.setTimeout(() => setSuggestOpen(false), 150)
                  }
                  onKeyDown={(e) => {
                    if (e.key !== "Enter") return;
                    const q = search.trim();
                    if (!q) return;
                    setSuggestOpen(false);
                    router.push(`/search?q=${encodeURIComponent(q)}`);
                  }}
                />
                {/* ⌘K hint */}
                <div className="absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none">
                  <kbd className="font-mono text-[10px] text-mist border border-hairline rounded-sm px-1.5 py-0.5 bg-vellum">
                    ⌘K
                  </kbd>
                </div>
                {/* Suggestions */}
                {suggestOpen && (suggestLoading || suggestions.length > 0) && (
                  <div className="absolute top-full mt-1 w-full bg-paper border border-hairline rounded-sm shadow-subtle overflow-hidden z-50">
                    {suggestLoading && (
                      <div className="px-3 py-2 text-[12px] text-mist">
                        Searching…
                      </div>
                    )}
                    {!suggestLoading && suggestions.length === 0 && (
                      <div className="px-3 py-2 text-[12px] text-mist">
                        No matches
                      </div>
                    )}
                    {!suggestLoading && suggestions.length > 0 && (
                      <ul>
                        {suggestions.map((s, idx) => (
                          <li key={`${s.href}-${idx}`}>
                            <button
                              type="button"
                              className="w-full text-left px-3 py-2 hover:bg-vellum/70"
                              onMouseDown={(e) => e.preventDefault()}
                              onClick={() => {
                                setSuggestOpen(false);
                                router.push(s.href);
                              }}
                            >
                              <div className="flex items-start justify-between gap-4">
                                <div className="min-w-0">
                                  <div className="text-[13px] text-ink truncate">
                                    {s.label}
                                  </div>
                                  {s.meta && (
                                    <div className="text-[11px] text-mist truncate mt-0.5">
                                      {s.meta}
                                    </div>
                                  )}
                                </div>
                                <span className="text-[11px] text-slate shrink-0">
                                  {s.group}
                                </span>
                              </div>
                            </button>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
              </div>
            </div>

            {/* Right cluster */}
            <div className="flex items-center gap-3 shrink-0">
              {/* Notification bell */}
              <NotificationBell />

              {/* Theme toggle */}
              <ThemeToggle variant="nav" />
            </div>
          </header>

          {/* Page content */}
          <div className="flex-1 min-w-0 overflow-y-auto">{children}</div>
        </div>
      </div>
    </div>
  );
}

// ─── Marketing nav ────────────────────────────────────────────────────────────

export function MarketingNav() {
  const [open, setOpen] = useState(false);
  const pathname = usePathname();

  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  return (
    <nav className="border-b border-hairline bg-paper/90 backdrop-blur sticky top-0 z-40">
      <div className="max-w-[1180px] mx-auto px-4 md:px-10 py-3 md:py-4 flex items-center justify-between gap-3 md:gap-6">
        <Monogram href="/" />
        <div className="hidden md:flex items-center gap-6">
          <DocsLink />
        </div>
        <button
          type="button"
          aria-label={open ? "Close menu" : "Open menu"}
          aria-expanded={open}
          onClick={() => setOpen((v) => !v)}
          className="md:hidden inline-flex items-center justify-center w-9 h-9 border border-hairline rounded-sm bg-paper hover:border-ink transition-colors"
        >
          <HamburgerIcon open={open} />
        </button>
      </div>
      {open && (
        <div className="md:hidden border-t border-hairline bg-paper px-6 py-5 flex flex-col divide-y divide-hairline border-y">
          <a
            href={DOCS_URL}
            target="_blank"
            rel="noreferrer"
            onClick={() => setOpen(false)}
            className="font-body text-[15px] text-graphite py-3"
          >
            Docs ↗
          </a>
        </div>
      )}
    </nav>
  );
}

"use client";

/**
 * Notifications context — workspace-scoped in-app inbox plus optional
 * browser-push surfacing.
 *
 * Sources of events
 * -----------------
 *  - Polling `/scans` every 60s and detecting state transitions:
 *    queued/running → done | failed. We persist the last-seen status per
 *    scan id so transitions are detected exactly once across reloads.
 *  - Local actions can call `notify()` directly (e.g. the findings page
 *    after assigning a finding to someone).
 *
 * Cross-user notifications (e.g. Alice assigns a finding to Bob)
 * require a server-side pub-sub channel that isn't wired yet. Until
 * then, the assignment notification only fires for the user who took
 * the action; that's still useful as a confirmation toast.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { api } from "./api";
import { useWorkspace } from "./workspace-context";

export type NotificationKind =
  | "assessment-done"
  | "assessment-failed"
  | "assignment"
  | "info";

export type AppNotification = {
  id: string;
  title: string;
  body?: string;
  href?: string;
  at: number;
  read: boolean;
  kind: NotificationKind;
};

type ContextValue = {
  notifications: AppNotification[];
  unreadCount: number;
  permission: NotificationPermission | "unsupported";
  requestPermission: () => Promise<void>;
  notify: (n: Omit<AppNotification, "id" | "at" | "read">) => void;
  markAllRead: () => void;
  remove: (id: string) => void;
  clear: () => void;
};

const NotificationsContext = createContext<ContextValue | null>(null);

const MAX_NOTIFICATIONS = 50;
const POLL_MS = 60_000;

type Scan = {
  id: string;
  target_id: string;
  status: string;
  grade: string | null;
  summary: Record<string, number | string> | null;
  finished_at: string | null;
  created_at: string;
};

type Target = { id: string; name: string };

function storageKey(workspaceId: string | null, suffix: string): string {
  return `pencheff.notifications.${workspaceId ?? "anon"}.${suffix}`;
}

function readJSON<T>(key: string, fallback: T): T {
  if (typeof window === "undefined") return fallback;
  try {
    const raw = window.localStorage.getItem(key);
    if (!raw) return fallback;
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function writeJSON(key: string, value: unknown): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* quota exceeded — silently drop, badges/permission still work */
  }
}

export function NotificationsProvider({ children }: { children: ReactNode }) {
  const { activeWorkspace } = useWorkspace();
  const workspaceId = activeWorkspace?.id ?? null;

  const [notifications, setNotifications] = useState<AppNotification[]>([]);
  const [permission, setPermission] = useState<NotificationPermission | "unsupported">(
    typeof window !== "undefined" && "Notification" in window
      ? Notification.permission
      : "unsupported"
  );

  // Last-seen status per scan id — drives transition detection.
  const lastStatusRef = useRef<Map<string, string>>(new Map());

  // Load persisted state when the workspace changes.
  useEffect(() => {
    const inbox = readJSON<AppNotification[]>(storageKey(workspaceId, "inbox"), []);
    setNotifications(inbox);
    const seen = readJSON<Record<string, string>>(storageKey(workspaceId, "scanStatus"), {});
    lastStatusRef.current = new Map(Object.entries(seen));
  }, [workspaceId]);

  // Persist inbox on every change.
  useEffect(() => {
    writeJSON(storageKey(workspaceId, "inbox"), notifications);
  }, [notifications, workspaceId]);

  const notify = useCallback((n: Omit<AppNotification, "id" | "at" | "read">) => {
    const entry: AppNotification = {
      ...n,
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      at: Date.now(),
      read: false,
    };
    setNotifications(prev => [entry, ...prev].slice(0, MAX_NOTIFICATIONS));

    // Surface as a real browser notification when permission is granted.
    if (typeof window !== "undefined" && "Notification" in window && Notification.permission === "granted") {
      try {
        const native = new Notification(entry.title, {
          body: entry.body,
          tag: `pencheff-${entry.kind}-${entry.id}`,
          icon: "/icon-192.png",
        });
        if (entry.href) {
          native.onclick = () => {
            window.focus();
            window.location.href = entry.href!;
            native.close();
          };
        }
      } catch {
        /* Notification can throw on some browsers (e.g. iOS) — drop silently */
      }
    }
  }, []);

  const requestPermission = useCallback(async () => {
    if (typeof window === "undefined" || !("Notification" in window)) {
      setPermission("unsupported");
      return;
    }
    try {
      const result = await Notification.requestPermission();
      setPermission(result);
    } catch {
      /* user-agent rejected */
    }
  }, []);

  const markAllRead = useCallback(() => {
    setNotifications(prev => prev.map(n => (n.read ? n : { ...n, read: true })));
  }, []);

  const remove = useCallback((id: string) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  }, []);

  const clear = useCallback(() => {
    setNotifications([]);
  }, []);

  // Polling loop: detect assessment state transitions per workspace.
  useEffect(() => {
    if (!workspaceId) return;
    let cancelled = false;
    let targets: Target[] = [];

    async function ensureTargets() {
      if (targets.length > 0) return;
      try {
        targets = await api<Target[]>("/targets");
      } catch {
        targets = [];
      }
    }

    async function tick() {
      try {
        const scans = await api<Scan[]>("/scans");
        if (cancelled) return;
        await ensureTargets();
        const targetById = new Map(targets.map(t => [t.id, t]));
        const prev = lastStatusRef.current;
        const next = new Map<string, string>();
        for (const s of scans) {
          next.set(s.id, s.status);
          const prevStatus = prev.get(s.id);
          if (!prevStatus) continue; // first time we see this scan — no transition
          if (prevStatus === s.status) continue;
          if (prevStatus === "done" || prevStatus === "failed") continue;
          if (s.status === "done") {
            const tName = targetById.get(s.target_id)?.name ?? "Target";
            const grade = s.grade ? ` · grade ${s.grade}` : "";
            const summary = s.summary
              ? ` · ${Number(s.summary.critical) || 0} crit · ${Number(s.summary.high) || 0} high`
              : "";
            notify({
              kind: "assessment-done",
              title: "Assessment complete",
              body: `${tName}${grade}${summary}`,
              href: `/scans/${s.id}`,
            });
          } else if (s.status === "failed") {
            const tName = targetById.get(s.target_id)?.name ?? "Target";
            notify({
              kind: "assessment-failed",
              title: "Assessment failed",
              body: tName,
              href: `/scans/${s.id}`,
            });
          }
        }
        lastStatusRef.current = next;
        writeJSON(storageKey(workspaceId, "scanStatus"), Object.fromEntries(next));
      } catch {
        /* network blip — try again next tick */
      }
    }

    // Bootstrap status map first (no notifications fired), then poll.
    api<Scan[]>("/scans").then(scans => {
      if (cancelled) return;
      const seed = new Map<string, string>();
      for (const s of scans) seed.set(s.id, s.status);
      // Merge with persisted state so the first poll can detect transitions
      // that happened while the tab was closed.
      const persisted = lastStatusRef.current;
      for (const [id, status] of persisted) {
        if (!seed.has(id)) continue;
        const live = seed.get(id);
        if (live === status) continue;
        if (status === "done" || status === "failed") continue;
        // Run the diff against the persisted state inside tick() on first run
      }
      // Use persisted state as the baseline for the first tick.
      if (persisted.size === 0) {
        lastStatusRef.current = seed;
        writeJSON(storageKey(workspaceId, "scanStatus"), Object.fromEntries(seed));
      }
    }).catch(() => {});

    tick();
    const handle = window.setInterval(tick, POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(handle);
    };
  }, [workspaceId, notify]);

  const unreadCount = useMemo(() => notifications.filter(n => !n.read).length, [notifications]);

  const value = useMemo<ContextValue>(() => ({
    notifications,
    unreadCount,
    permission,
    requestPermission,
    notify,
    markAllRead,
    remove,
    clear,
  }), [notifications, unreadCount, permission, requestPermission, notify, markAllRead, remove, clear]);

  return (
    <NotificationsContext.Provider value={value}>
      {children}
    </NotificationsContext.Provider>
  );
}

export function useNotifications(): ContextValue {
  const ctx = useContext(NotificationsContext);
  if (!ctx) {
    throw new Error("useNotifications must be used inside <NotificationsProvider>");
  }
  return ctx;
}

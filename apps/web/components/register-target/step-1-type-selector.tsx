"use client";

import { useMemo, useState } from "react";
import { Button } from "@/components/brutal";
import { cn } from "@/lib/cn";
import {
  CATEGORIES,
  SELECT_ALL_IDS,
  TYPES_BY_ID,
  type TargetCategory,
  type TargetType,
} from "./target-types";
import {
  DISCIPLINES,
  DISCIPLINE_CATEGORY_LABEL,
  TYPE_ID_TO_DISCIPLINES,
  type Discipline,
  type DisciplineCategory,
  type DisciplineId,
} from "./disciplines";

// ─── Category icons ────────────────────────────────────────────────────────

function WebApiIcon() {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden
    >
      <circle cx="8" cy="8" r="6.5" />
      <path d="M1.5 8h13M8 1.5a9 9 0 0 1 0 13M8 1.5a9 9 0 0 0 0 13" />
    </svg>
  );
}
function CodeIcon() {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden
    >
      <path d="M5 4L1.5 8 5 12M11 4l3.5 4-3.5 4M9.5 3l-3 10" />
    </svg>
  );
}
function CloudIcon() {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden
    >
      <path d="M12.5 10.5a3 3 0 0 0 0-6 3 3 0 0 0-5.83-1A3 3 0 1 0 4 10.5" />
      <rect x="3.5" y="10.5" width="9" height="4" rx="0.5" />
    </svg>
  );
}
function NetworkIcon() {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden
    >
      <circle cx="8" cy="3" r="1.5" />
      <circle cx="3" cy="13" r="1.5" />
      <circle cx="13" cy="13" r="1.5" />
      <path d="M8 4.5v3M8 7.5L3 11.5M8 7.5l5 4" />
    </svg>
  );
}
function AiIcon() {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden
    >
      <path d="M8 2v2M8 12v2M2 8h2M12 8h2M4.1 4.1l1.4 1.4M10.5 10.5l1.4 1.4M4.1 11.9l1.4-1.4M10.5 5.5l1.4-1.4" />
      <circle cx="8" cy="8" r="2.5" />
    </svg>
  );
}
function MobileIcon() {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden
    >
      <rect x="4.5" y="1.5" width="7" height="13" rx="1" />
      <path d="M7 13.5h2" />
    </svg>
  );
}
function OtIcon() {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden
    >
      <rect x="1.5" y="4.5" width="13" height="7" rx="0.5" />
      <path d="M4 4.5V3M8 4.5V3M12 4.5V3M4 11.5v1.5M8 11.5v1.5M12 11.5v1.5" />
      <circle cx="5.5" cy="8" r="1" fill="currentColor" stroke="none" />
      <circle cx="10.5" cy="8" r="1" fill="currentColor" stroke="none" />
    </svg>
  );
}
function IdentityIcon() {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden
    >
      <path d="M8 1.5L2 4.5v4c0 3.5 2.5 5.5 6 6.5 3.5-1 6-3 6-6.5v-4L8 1.5z" />
      <circle cx="8" cy="7" r="2" />
      <path d="M4 13a5 5 0 0 1 8 0" />
    </svg>
  );
}

const CATEGORY_META: Record<
  string,
  {
    icon: React.ReactNode;
    iconBg: string;
    iconFg: string;
  }
> = {
  "web-api": {
    icon: <WebApiIcon />,
    iconBg: "bg-gilt/10",
    iconFg: "text-gilt",
  },
  "code-supply": {
    icon: <CodeIcon />,
    iconBg: "bg-graphite/10",
    iconFg: "text-graphite",
  },
  "infra-cloud": {
    icon: <CloudIcon />,
    iconBg: "bg-vellum",
    iconFg: "text-slate",
  },
  "network-host": {
    icon: <NetworkIcon />,
    iconBg: "bg-vellum",
    iconFg: "text-graphite",
  },
  "ai-llm": {
    icon: <AiIcon />,
    iconBg: "bg-coral/20",
    iconFg: "text-graphite",
  },
  "mobile-client": {
    icon: <MobileIcon />,
    iconBg: "bg-lime/20",
    iconFg: "text-graphite",
  },
  "ot-iot": { icon: <OtIcon />, iconBg: "bg-vellum", iconFg: "text-graphite" },
  "identity-compliance": {
    icon: <IdentityIcon />,
    iconBg: "bg-forest/10",
    iconFg: "text-forest",
  },
};

// ─── Type card icons (compact, colored) ────────────────────────────────────

function TypeIcon({ id }: { id: string }) {
  const icons: Record<string, React.ReactNode> = {
    "web-app": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <circle cx="8" cy="8" r="6.5" />
        <path d="M1.5 8h13M8 1.5a9 9 0 0 1 0 13M8 1.5a9 9 0 0 0 0 13" />
      </svg>
    ),
    "rest-api": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <path d="M5 4L1.5 8 5 12M11 4l3.5 4-3.5 4" />
      </svg>
    ),
    "graphql-api": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <polygon points="8,1.5 14,5 14,11 8,14.5 2,11 2,5" />
        <circle cx="8" cy="8" r="1.5" fill="currentColor" stroke="none" />
      </svg>
    ),
    websocket: (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <path d="M2 8h4l2-4 2 8 2-4h2" />
      </svg>
    ),
    grpc: (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <rect x="1.5" y="5.5" width="5" height="5" rx="0.5" />
        <rect x="9.5" y="5.5" width="5" height="5" rx="0.5" />
        <path d="M6.5 8h3" />
      </svg>
    ),
    "source-code-repo": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <circle cx="4" cy="4" r="2" />
        <circle cx="4" cy="12" r="2" />
        <circle cx="12" cy="4" r="2" />
        <path d="M4 6v4M6 4h2a2 2 0 0 1 2 2v4" />
      </svg>
    ),
    "cicd-pipeline": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <rect x="1.5" y="5.5" width="3" height="5" rx="0.5" />
        <rect x="6.5" y="5.5" width="3" height="5" rx="0.5" />
        <rect x="11.5" y="5.5" width="3" height="5" rx="0.5" />
        <path d="M4.5 8h2M9.5 8h2" />
      </svg>
    ),
    iac: (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <rect x="2" y="2" width="12" height="12" rx="0.5" />
        <path d="M2 6h12M6 6v8" />
      </svg>
    ),
    "container-image": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <path d="M8 1.5L14 5v6L8 14.5 2 11V5L8 1.5z" />
        <path d="M8 1.5v13M2 5l6 3.5L14 5" />
      </svg>
    ),
    kubernetes: (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <circle cx="8" cy="8" r="6.5" />
        <circle cx="8" cy="8" r="2" />
        <path d="M8 1.5v3M8 11.5v3M1.5 8h3M11.5 8h3" />
      </svg>
    ),
    "package-registry": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <path d="M8 1.5L14 5v6L8 14.5 2 11V5L8 1.5z" />
        <path d="M8 8.5L14 5M8 8.5L2 5M8 8.5v6" />
      </svg>
    ),
    "sbom-deps": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <rect x="2" y="2" width="12" height="12" rx="0.5" />
        <path d="M5 6h6M5 8.5h6M5 11h4" />
      </svg>
    ),
    "cloud-account": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <path d="M12 10a3 3 0 0 0 0-6 3 3 0 0 0-5.83-1A3 3 0 1 0 4 10" />
        <path d="M3.5 10h9" />
      </svg>
    ),
    serverless: (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <path d="M9 2H4L2 8h5l-1 6 8-8H9l1-4z" />
      </svg>
    ),
    "cloud-storage": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <ellipse cx="8" cy="5" rx="5.5" ry="2" />
        <path d="M2.5 5v6c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2V5" />
        <path d="M2.5 8c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2" />
      </svg>
    ),
    "load-balancer-cdn": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <circle cx="8" cy="3" r="1.5" />
        <circle cx="3" cy="12" r="1.5" />
        <circle cx="13" cy="12" r="1.5" />
        <path d="M8 4.5L3 10.5M8 4.5l5 6" />
      </svg>
    ),
    "database-cloud": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <ellipse cx="8" cy="4" rx="5.5" ry="2" />
        <path d="M2.5 4v8c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2V4" />
        <path d="M2.5 8c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2" />
      </svg>
    ),
    "secrets-manager": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <rect x="3.5" y="7" width="9" height="7.5" rx="0.5" />
        <circle cx="8" cy="4.5" r="2.5" />
        <circle cx="8" cy="10.5" r="1" fill="currentColor" stroke="none" />
      </svg>
    ),
    "network-host": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <rect x="1.5" y="4" width="13" height="8" rx="0.5" />
        <path d="M5 12v2.5M11 12v2.5M3 14.5h10M8 7.5v1" />
        <circle cx="8" cy="6.5" r="1" fill="currentColor" stroke="none" />
      </svg>
    ),
    "tls-ssl": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <path d="M8 1.5L2 4.5v4c0 3.5 2.5 5.5 6 6.5 3.5-1 6-3 6-6.5v-4L8 1.5z" />
        <path d="M5.5 8l1.5 1.5L10.5 6" />
      </svg>
    ),
    "dns-subdomain": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <circle cx="8" cy="8" r="6.5" />
        <path d="M1.5 8h13M8 1.5a9 9 0 0 1 0 13M8 1.5a9 9 0 0 0 0 13" />
      </svg>
    ),
    "email-security": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <rect x="1.5" y="3.5" width="13" height="9" rx="0.5" />
        <path d="M1.5 5l6.5 5 6.5-5" />
      </svg>
    ),
    "vpn-remote": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <circle cx="5" cy="8" r="3.5" />
        <path d="M8.5 8h6M11.5 5.5l3 2.5-3 2.5" />
      </svg>
    ),
    "internal-network": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <circle cx="8" cy="8" r="1.5" />
        <circle cx="2.5" cy="4" r="1.5" />
        <circle cx="13.5" cy="4" r="1.5" />
        <circle cx="2.5" cy="12" r="1.5" />
        <circle cx="13.5" cy="12" r="1.5" />
        <path d="M4 4h9M4 12h9M8 6.5v-2M3.5 5.3 6.5 7M9.5 7l3-1.7M3.5 10.7 6.5 9M9.5 9l3 1.7" />
      </svg>
    ),
    "llm-endpoint": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <path d="M8 2v2M8 12v2M2 8h2M12 8h2M4.1 4.1l1.4 1.4M10.5 10.5l1.4 1.4M4.1 11.9l1.4-1.4M10.5 5.5l1.4-1.4" />
        <circle cx="8" cy="8" r="2.5" />
      </svg>
    ),
    "mcp-server": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <rect x="3" y="3" width="4" height="4" rx="0.5" />
        <rect x="9" y="3" width="4" height="4" rx="0.5" />
        <rect x="3" y="9" width="4" height="4" rx="0.5" />
        <rect x="9" y="9" width="4" height="4" rx="0.5" />
        <path d="M7 5h2M5 7v2M11 7v2M7 11h2" />
      </svg>
    ),
    "ai-agent": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
        aria-hidden
      >
        <rect x="3" y="5.5" width="10" height="7" rx="1.5" />
        <path d="M8 2.5v3" />
        <circle cx="8" cy="2" r="0.75" fill="currentColor" stroke="none" />
        <circle cx="6" cy="9" r="0.75" fill="currentColor" stroke="none" />
        <circle cx="10" cy="9" r="0.75" fill="currentColor" stroke="none" />
        <path d="M1.5 8.5v1.5M14.5 8.5v1.5" />
      </svg>
    ),
    "rag-vector-db": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <ellipse cx="8" cy="4" rx="5.5" ry="2" />
        <path d="M2.5 4v3c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2V4" />
        <path d="M2.5 7v3c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2V7" />
        <path d="M2.5 10v2c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2v-2" />
      </svg>
    ),
    "ml-model": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <circle cx="3" cy="5" r="1.5" />
        <circle cx="3" cy="11" r="1.5" />
        <circle cx="13" cy="8" r="1.5" />
        <circle cx="8" cy="3" r="1.5" />
        <circle cx="8" cy="13" r="1.5" />
        <path d="M4.5 5.5L7 4M4.5 10.5L7 12M4.5 6l7 2.5M4.5 10 11.5 8" />
      </svg>
    ),
    "voice-speech-ai": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <path d="M1.5 8h1.5l1.5-3 2 6 2-6 1.5 3h5.5" />
      </svg>
    ),
    "agent-memory": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
        aria-hidden
      >
        <path d="M8 1.5 14.5 5 8 8.5 1.5 5z" />
        <path d="M1.5 8 8 11.5 14.5 8" />
        <path d="M1.5 11 8 14.5 14.5 11" />
      </svg>
    ),
    "android-app": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <path d="M3 11V7a5 5 0 0 1 10 0v4" />
        <rect x="1.5" y="11" width="13" height="3" rx="0.5" />
        <path d="M2 3l2 2M14 3l-2 2" />
      </svg>
    ),
    "ios-app": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <rect x="4" y="1.5" width="8" height="13" rx="1.5" />
        <circle cx="8" cy="12.5" r="0.75" fill="currentColor" stroke="none" />
        <path d="M6.5 1.5h3" />
      </svg>
    ),
    "browser-extension": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <rect x="1.5" y="3" width="13" height="10" rx="0.5" />
        <path d="M1.5 6h13" />
        <circle cx="4" cy="4.5" r="0.75" fill="currentColor" stroke="none" />
        <circle cx="6.5" cy="4.5" r="0.75" fill="currentColor" stroke="none" />
      </svg>
    ),
    "desktop-app": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <rect x="1.5" y="2.5" width="13" height="9" rx="0.5" />
        <path d="M5 14.5h6M8 11.5v3" />
      </svg>
    ),
    firmware: (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <rect x="2" y="4" width="12" height="8" rx="0.5" />
        <path d="M5 4V2.5M8 4V2.5M11 4V2.5M5 12v1.5M8 12v1.5M11 12v1.5" />
        <rect x="4.5" y="6" width="7" height="4" rx="0.5" />
      </svg>
    ),
    "iot-device": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <rect x="3" y="5" width="10" height="7" rx="0.5" />
        <path d="M6 5V3.5M10 5V3.5" />
        <circle cx="6.5" cy="8.5" r="1" fill="currentColor" stroke="none" />
        <circle cx="9.5" cy="8.5" r="1" fill="currentColor" stroke="none" />
      </svg>
    ),
    "ot-ics-scada": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <rect x="1.5" y="4.5" width="13" height="7" rx="0.5" />
        <circle cx="5" cy="8" r="1.5" />
        <circle cx="11" cy="8" r="1.5" />
        <path d="M6.5 8h3" />
      </svg>
    ),
    "identity-provider": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <circle cx="8" cy="5" r="3" />
        <path d="M2 14a6 6 0 0 1 12 0" />
      </svg>
    ),
    "database-store": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <ellipse cx="8" cy="4" rx="5.5" ry="2" />
        <path d="M2.5 4v8c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2V4" />
        <path d="M2.5 8c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2" />
      </svg>
    ),
    "compliance-posture": (
      <svg
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <rect x="3" y="1.5" width="10" height="13" rx="0.5" />
        <path d="M5.5 6l1.5 1.5L10.5 5M5.5 10h5" />
      </svg>
    ),
  };
  return (icons[id] ?? null) as React.ReactNode;
}

// ─── Type card ─────────────────────────────────────────────────────────────

function TypeCard({
  type,
  selected,
  onToggle,
}: {
  type: TargetType;
  selected: boolean;
  onToggle: () => void;
}) {
  const isComingSoon = type.status === "coming-soon";
  const meta = CATEGORY_META[type.categoryId];
  return (
    <button
      type="button"
      disabled={isComingSoon}
      onClick={onToggle}
      aria-pressed={selected}
      aria-label={isComingSoon ? `${type.label} — coming soon` : type.label}
      className={cn(
        "relative text-left border rounded-sm p-3 transition-colors duration-150",
        "flex flex-col gap-2",
        selected
          ? "border-ink bg-vellum shadow-subtle"
          : isComingSoon
            ? "border-hairline bg-paper opacity-50 cursor-not-allowed"
            : "border-hairline bg-paper hover:border-graphite hover:bg-vellum/60 cursor-pointer",
      )}
    >
      {/* Checkbox */}
      <span
        className={cn(
          "absolute top-2.5 right-2.5 w-[14px] h-[14px] rounded-sm border flex items-center justify-center shrink-0",
          selected
            ? "bg-ink border-ink text-paper"
            : "border-hairline bg-paper",
        )}
        aria-hidden
      >
        {selected && (
          <span className="text-[9px] leading-none font-bold">✓</span>
        )}
      </span>

      {/* Icon */}
      <span
        className={cn(
          "w-7 h-7 rounded-sm flex items-center justify-center shrink-0",
          meta?.iconBg ?? "bg-vellum",
          meta?.iconFg ?? "text-graphite",
        )}
      >
        <span className="w-4 h-4">
          <TypeIcon id={type.id} />
        </span>
      </span>

      {/* Content */}
      <div className="pr-4">
        <span className="block font-body font-medium text-[12px] text-ink leading-snug">
          {type.num}. {type.label}
        </span>
        <span className="block font-mono text-[10px] text-mist mt-0.5 leading-snug">
          {type.description}
        </span>
      </div>

      {isComingSoon && (
        <span className="absolute bottom-2 right-2 font-mono text-[8px] uppercase tracking-[0.14em] text-mist">
          Soon
        </span>
      )}
    </button>
  );
}

// ─── Category section ──────────────────────────────────────────────────────

function CategorySection({
  category,
  selectedIds,
  onToggle,
}: {
  category: TargetCategory;
  selectedIds: Set<string>;
  onToggle: (id: string) => void;
}) {
  const meta = CATEGORY_META[category.id];
  const activeCount = category.types.filter(
    (t) => t.status === "active",
  ).length;
  return (
    <section className="mt-8">
      <div className="flex items-center justify-between mb-3 pb-2 border-b border-hairline">
        <div className="flex items-center gap-2.5">
          <span
            className={cn(
              "w-6 h-6 rounded-sm flex items-center justify-center shrink-0",
              meta?.iconBg ?? "bg-vellum",
              meta?.iconFg ?? "text-graphite",
            )}
          >
            <span className="w-3.5 h-3.5">{meta?.icon}</span>
          </span>
          <span className="font-body font-semibold text-[13px] text-ink tracking-[0.02em]">
            {category.label}
          </span>
        </div>
        <span className="font-mono text-[11px] text-mist">
          {activeCount} target{activeCount !== 1 ? "s" : ""}
        </span>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2.5">
        {category.types.map((type) => (
          <TypeCard
            key={type.id}
            type={type}
            selected={selectedIds.has(type.id)}
            onToggle={() => onToggle(type.id)}
          />
        ))}
      </div>
    </section>
  );
}

// ─── Sticky bottom bar ─────────────────────────────────────────────────────

function StickyBottomBar({
  selectedCount,
  hasSupportedSelection,
  onContinue,
  onCancel,
}: {
  selectedCount: number;
  hasSupportedSelection: boolean;
  onContinue: () => void;
  onCancel: () => void;
}) {
  return (
    <div className="fixed bottom-0 left-0 md:left-[280px] right-0 z-30 border-t border-hairline bg-paper/95 backdrop-blur">
      <div className="max-w-[1400px] mx-auto px-5 md:px-6 py-3.5 flex items-center justify-between gap-6">
        <div className="flex items-center gap-2 min-w-0">
          <span
            className="w-2 h-2 rounded-full bg-hairline shrink-0"
            aria-hidden
          />
          <span className="font-body text-[13px] text-slate truncate">
            {selectedCount === 0
              ? "Select target types to continue"
              : `${selectedCount} target type${selectedCount !== 1 ? "s" : ""} selected`}
          </span>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <Button variant="yellow" type="button" onClick={onCancel}>
            Cancel
          </Button>
          <Button
            variant="pink"
            type="button"
            disabled={!hasSupportedSelection}
            onClick={onContinue}
          >
            Continue →
          </Button>
        </div>
      </div>
    </div>
  );
}

// ─── Discipline panel ──────────────────────────────────────────────────────

function DisciplineCard({
  discipline,
  state,
  onToggle,
}: {
  discipline: Discipline;
  // selected | partial (some typeIds checked but not all owned by this disc) | unselected
  state: "selected" | "partial" | "unselected";
  onToggle: () => void;
}) {
  const isSelected = state === "selected";
  const isPartial = state === "partial";
  return (
    <button
      type="button"
      onClick={onToggle}
      aria-pressed={isSelected}
      className={cn(
        "text-left border rounded-sm p-4 transition-colors flex flex-col gap-2 h-full",
        isSelected
          ? "border-ink bg-vellum"
          : isPartial
            ? "border-gilt/60 bg-paper"
            : "border-hairline bg-paper hover:border-ink",
      )}
    >
      <div className="flex items-baseline justify-between gap-3">
        <span className="font-mono text-[12px] font-semibold tracking-[0.04em] text-ink">
          {discipline.label}
        </span>
        {isSelected && (
          <span className="font-mono text-[10px] text-emerald" aria-hidden>
            ✓ selected
          </span>
        )}
        {isPartial && (
          <span className="font-mono text-[10px] text-gilt" aria-hidden>
            partial
          </span>
        )}
      </div>
      <span className="font-body text-[12px] text-slate">
        {discipline.longLabel}
      </span>
      <span className="font-mono text-[11px] text-mist leading-snug">
        {discipline.description}
      </span>
      <span className="mt-1 font-mono text-[10px] text-mist">
        fans out →{" "}
        {discipline.typeIds
          .map((id) => TYPES_BY_ID[id]?.label || id)
          .join(" · ")}
      </span>
    </button>
  );
}

function DisciplinePanel({
  byCategory,
  selectedDisciplines,
  selectedIds,
  onToggle,
}: {
  byCategory: Record<DisciplineCategory, Discipline[]>;
  selectedDisciplines: Set<DisciplineId>;
  selectedIds: Set<string>;
  onToggle: (id: DisciplineId) => void;
}) {
  function stateOf(d: Discipline): "selected" | "partial" | "unselected" {
    if (selectedDisciplines.has(d.id)) return "selected";
    // Partial: some of this discipline's typeIds happen to be checked by hand
    // or via a different discipline.
    const anyChecked = d.typeIds.some((id) => selectedIds.has(id));
    return anyChecked ? "partial" : "unselected";
  }
  const categories: DisciplineCategory[] = [
    "cloud",
    "cnapp",
    "appsec",
    "ai",
    "supply_chain",
  ];
  return (
    <>
      {categories.map((catId) => {
        const list = byCategory[catId];
        if (!list?.length) return null;
        return (
          <section key={catId} className="mt-8">
            <div className="flex items-center justify-between mb-3 pb-2 border-b border-hairline">
              <span className="font-body font-semibold text-[13px] text-ink tracking-[0.02em]">
                {DISCIPLINE_CATEGORY_LABEL[catId]}
              </span>
              <span className="font-mono text-[11px] text-mist">
                {list.length} discipline{list.length !== 1 ? "s" : ""}
              </span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {list.map((d) => (
                <DisciplineCard
                  key={d.id}
                  discipline={d}
                  state={stateOf(d)}
                  onToggle={() => onToggle(d.id)}
                />
              ))}
            </div>
          </section>
        );
      })}
    </>
  );
}

// ─── Main component ────────────────────────────────────────────────────────

export function Step1TypeSelector({
  selectedIds,
  onChange,
  selectedDisciplines,
  onDisciplineChange,
  onContinue,
  onCancel,
}: {
  selectedIds: Set<string>;
  onChange: (ids: Set<string>) => void;
  /** When omitted, the discipline tab is hidden (legacy embedders). */
  selectedDisciplines?: Set<DisciplineId>;
  onDisciplineChange?: (ids: Set<DisciplineId>) => void;
  onContinue: () => void;
  onCancel: () => void;
}) {
  const disciplineMode =
    selectedDisciplines !== undefined && onDisciplineChange !== undefined;
  const [tab, setTab] = useState<"discipline" | "type">("type");

  function toggle(id: string) {
    const next = new Set(selectedIds);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    onChange(next);

    // If we're in discipline mode and the user manually toggled a type card
    // that was contributed by an active discipline, prune the discipline so
    // the UI stops claiming it's selected (the type is now hand-managed).
    if (disciplineMode && selectedDisciplines) {
      const owningDisciplines = TYPE_ID_TO_DISCIPLINES[id] ?? [];
      if (owningDisciplines.length > 0 && !next.has(id)) {
        const dn = new Set(selectedDisciplines);
        let changed = false;
        for (const d of owningDisciplines) {
          if (dn.has(d)) {
            dn.delete(d);
            changed = true;
          }
        }
        if (changed) onDisciplineChange!(dn);
      }
    }
  }

  function toggleDiscipline(id: DisciplineId) {
    if (!disciplineMode || !selectedDisciplines) return;
    const dn = new Set(selectedDisciplines);
    const tn = new Set(selectedIds);
    const disc = DISCIPLINES.find((d) => d.id === id);
    if (!disc) return;

    if (dn.has(id)) {
      // Deselecting — remove the discipline, then remove its typeIds only if
      // no other still-selected discipline owns them.
      dn.delete(id);
      for (const tid of disc.typeIds) {
        const stillOwned = (TYPE_ID_TO_DISCIPLINES[tid] ?? []).some(
          (d2) => d2 !== id && dn.has(d2),
        );
        if (!stillOwned) tn.delete(tid);
      }
    } else {
      dn.add(id);
      for (const tid of disc.typeIds) tn.add(tid);
    }
    onDisciplineChange!(dn);
    onChange(tn);
  }

  function selectAll() {
    onChange(new Set(SELECT_ALL_IDS));
  }

  function clearAll() {
    onChange(new Set());
    if (disciplineMode) onDisciplineChange!(new Set());
  }

  const hasSupportedSelection = [...selectedIds].some(
    (id) => TYPES_BY_ID[id]?.kind !== null,
  );

  // Group disciplines by their category for the panel layout.
  const disciplinesByCategory = useMemo(() => {
    const out: Record<DisciplineCategory, Discipline[]> = {
      cloud: [],
      cnapp: [],
      appsec: [],
      ai: [],
      supply_chain: [],
    };
    for (const d of DISCIPLINES) out[d.category].push(d);
    return out;
  }, []);

  return (
    <div className="pb-24">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4 mb-2">
        <div>
          <p className="eyebrow-gilt">Registration</p>
          <h1 className="mt-3 font-display text-[36px] md:text-[40px] leading-[1.05] tracking-[-0.015em] text-ink">
            Register Target
          </h1>
          <p className="mt-2 text-[14px] text-slate max-w-[56ch]">
            {tab === "type"
              ? "Select one or more target types to scan. You can add multiple targets later."
              : "Pick a security discipline. We'll auto-select the right target types and apply matching scan defaults."}
          </p>
        </div>
        <div className="flex items-center gap-3 shrink-0 mt-1">
          <button
            type="button"
            onClick={selectAll}
            className="font-body text-[12px] font-medium text-gilt border border-gilt/40 rounded-sm px-3 py-1.5 hover:bg-gilt/5 transition-colors"
          >
            Select All ({SELECT_ALL_IDS.length})
          </button>
          <span className="text-hairline text-[11px]">|</span>
          <button
            type="button"
            onClick={clearAll}
            className="font-body text-[12px] font-medium text-slate hover:text-ink transition-colors"
          >
            Clear All
          </button>
        </div>
      </div>

      {disciplineMode && (
        <div className="mt-6 border-b border-hairline flex items-end gap-1">
          {[
            { id: "type", label: "By Target Type" },
            { id: "discipline", label: "By Discipline" },
          ].map((t) => {
            const active = tab === t.id;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => setTab(t.id as "discipline" | "type")}
                className={cn(
                  "font-body text-[13px] px-4 py-2 -mb-px border-b-2 transition-colors",
                  active
                    ? "border-ink text-ink font-semibold"
                    : "border-transparent text-slate hover:text-ink",
                )}
                aria-current={active ? "true" : undefined}
              >
                {t.label}
              </button>
            );
          })}
        </div>
      )}

      {tab === "discipline" && disciplineMode && selectedDisciplines && (
        <DisciplinePanel
          byCategory={disciplinesByCategory}
          selectedDisciplines={selectedDisciplines}
          selectedIds={selectedIds}
          onToggle={toggleDiscipline}
        />
      )}

      {tab === "type" && (
        // Category sections (existing target-type browser)
        <>
          {CATEGORIES.map((category) => (
            <CategorySection
              key={category.id}
              category={category}
              selectedIds={selectedIds}
              onToggle={toggle}
            />
          ))}
        </>
      )}

      <StickyBottomBar
        selectedCount={selectedIds.size}
        hasSupportedSelection={hasSupportedSelection}
        onContinue={onContinue}
        onCancel={onCancel}
      />
    </div>
  );
}

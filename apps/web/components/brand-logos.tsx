"use client";

import { cn } from "@/lib/cn";

type LogoProps = { className?: string };

const Slack = ({ className }: LogoProps) => (
  <svg viewBox="0 0 32 32" className={className} aria-hidden>
    <path
      fill="#E01E5A"
      d="M8.6 19.4a2.4 2.4 0 1 1-2.4-2.4h2.4v2.4Zm1.2 0a2.4 2.4 0 1 1 4.8 0v6a2.4 2.4 0 1 1-4.8 0v-6Z"
    />
    <path
      fill="#36C5F0"
      d="M12.2 8.6a2.4 2.4 0 1 1 2.4-2.4v2.4h-2.4Zm0 1.2a2.4 2.4 0 1 1 0 4.8h-6a2.4 2.4 0 1 1 0-4.8h6Z"
    />
    <path
      fill="#2EB67D"
      d="M23 12.2a2.4 2.4 0 1 1 2.4 2.4H23v-2.4Zm-1.2 0a2.4 2.4 0 1 1-4.8 0v-6a2.4 2.4 0 1 1 4.8 0v6Z"
    />
    <path
      fill="#ECB22E"
      d="M19.4 23a2.4 2.4 0 1 1-2.4 2.4V23h2.4Zm0-1.2a2.4 2.4 0 1 1 0-4.8h6a2.4 2.4 0 1 1 0 4.8h-6Z"
    />
  </svg>
);

const Teams = ({ className }: LogoProps) => (
  <svg viewBox="0 0 32 32" className={className} aria-hidden>
    <rect x="3" y="9" width="14" height="14" rx="1.5" fill="#5059C9" />
    <text
      x="10"
      y="20.5"
      fontFamily="Inter, system-ui, sans-serif"
      fontSize="11"
      fontWeight="700"
      fill="#fff"
      textAnchor="middle"
    >
      T
    </text>
    <circle cx="23" cy="11" r="3" fill="#7B83EB" />
    <path
      d="M18 14h10a1 1 0 0 1 1 1v7a4 4 0 0 1-4 4h-3a4 4 0 0 1-4-4v-8Z"
      fill="#7B83EB"
    />
  </svg>
);

const GoogleChat = ({ className }: LogoProps) => (
  <svg viewBox="0 0 32 32" className={className} aria-hidden>
    <path
      d="M5 7a2 2 0 0 1 2-2h18a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-8l-5 4v-4H7a2 2 0 0 1-2-2V7Z"
      fill="#00897B"
    />
    <circle cx="12" cy="14" r="1.6" fill="#fff" />
    <circle cx="16" cy="14" r="1.6" fill="#fff" />
    <circle cx="20" cy="14" r="1.6" fill="#fff" />
  </svg>
);

const Discord = ({ className }: LogoProps) => (
  <svg viewBox="0 0 32 32" className={className} aria-hidden>
    <path
      fill="#5865F2"
      d="M25.5 8.2A20 20 0 0 0 20.6 7l-.3.5a17 17 0 0 0-4.5 0L15.5 7a20 20 0 0 0-5 1.2A22 22 0 0 0 6.4 20a20 20 0 0 0 6.1 3l1.2-2a13 13 0 0 1-2-1l.5-.3a13 13 0 0 0 11.7 0l.5.3a13 13 0 0 1-2 1l1.2 2a20 20 0 0 0 6.1-3 22 22 0 0 0-4.2-11.8ZM12.3 18.1c-1.2 0-2.2-1.1-2.2-2.4 0-1.3 1-2.4 2.2-2.4 1.3 0 2.3 1.1 2.2 2.4 0 1.3-1 2.4-2.2 2.4Zm7.4 0c-1.2 0-2.2-1.1-2.2-2.4 0-1.3 1-2.4 2.2-2.4 1.3 0 2.3 1.1 2.2 2.4 0 1.3-1 2.4-2.2 2.4Z"
    />
  </svg>
);

const PagerDuty = ({ className }: LogoProps) => (
  <svg viewBox="0 0 32 32" className={className} aria-hidden>
    <rect x="5" y="5" width="22" height="22" rx="2" fill="#06AC38" />
    <path
      d="M11 9h7.5a5.5 5.5 0 0 1 0 11H14v3.5h-3V9Zm3 3v5h4.3a2.5 2.5 0 0 0 0-5H14Z"
      fill="#fff"
    />
  </svg>
);

const Opsgenie = ({ className }: LogoProps) => (
  <svg viewBox="0 0 32 32" className={className} aria-hidden>
    <path d="M16 4 5 11l4 13 7 4 7-4 4-13L16 4Z" fill="#172B4D" />
    <path d="M16 4v24l-7-4 7-20Z" fill="#2684FF" opacity=".85" />
    <path d="M11 13h10l-5 8-5-8Z" fill="#FFAB00" />
  </svg>
);

const Email = ({ className }: LogoProps) => (
  <svg viewBox="0 0 32 32" className={className} aria-hidden>
    <rect
      x="4"
      y="8"
      width="24"
      height="16"
      rx="1.5"
      fill="none"
      stroke="#171717"
      strokeWidth="1.6"
    />
    <path
      d="M5 9l11 8 11-8"
      fill="none"
      stroke="#171717"
      strokeWidth="1.6"
      strokeLinejoin="round"
    />
  </svg>
);

const Splunk = ({ className }: LogoProps) => (
  <svg viewBox="0 0 32 32" className={className} aria-hidden>
    <path d="M5 7l16 8.5L5 24v-4l10-4.5L5 11V7Z" fill="#65A637" />
    <rect x="22" y="20" width="5" height="4" fill="#F7931E" />
  </svg>
);

const Datadog = ({ className }: LogoProps) => (
  <svg viewBox="0 0 32 32" className={className} aria-hidden>
    <path d="M27 5 9 11l4 5-7 2 5 4-3 5h17a4 4 0 0 0 4-4V5Z" fill="#632CA6" />
    <path d="M14 14l4 8-7-3 3-5Z" fill="#fff" opacity=".9" />
    <circle cx="20" cy="14" r="1.8" fill="#fff" />
    <circle cx="20" cy="14" r="0.8" fill="#632CA6" />
  </svg>
);

const Jira = ({ className }: LogoProps) => (
  <svg viewBox="0 0 24 24" className={className} aria-hidden>
    <path
      fill="#2684FF"
      d="M11.571 11.513H0a5.218 5.218 0 0 0 5.232 5.215h2.13v2.057A5.215 5.215 0 0 0 12.575 24V12.518a1.005 1.005 0 0 0-1.004-1.005zm5.723-5.756H5.736a5.215 5.215 0 0 0 5.215 5.214h2.129v2.058a5.218 5.218 0 0 0 5.215 5.214V6.758a1.001 1.001 0 0 0-1.001-1.001zM23.013 0H11.455a5.215 5.215 0 0 0 5.215 5.215h2.129v2.057A5.215 5.215 0 0 0 24 12.483V1.005A1.001 1.001 0 0 0 23.013 0z"
    />
  </svg>
);

const GitHub = ({ className }: LogoProps) => (
  <svg viewBox="0 0 32 32" className={className} aria-hidden>
    <path
      fill="#171717"
      d="M16 4a12 12 0 0 0-3.8 23.4c.6.1.8-.3.8-.6v-2.2c-3.3.7-4-1.6-4-1.6-.6-1.4-1.4-1.8-1.4-1.8-1.1-.7.1-.7.1-.7 1.2.1 1.8 1.2 1.8 1.2 1.1 1.8 2.8 1.3 3.5 1 .1-.8.4-1.3.8-1.6-2.7-.3-5.5-1.3-5.5-5.9 0-1.3.5-2.4 1.2-3.2-.1-.3-.5-1.5.1-3.2 0 0 1-.3 3.3 1.2a11.5 11.5 0 0 1 6 0c2.3-1.5 3.3-1.2 3.3-1.2.7 1.7.3 2.9.1 3.2.8.8 1.2 1.9 1.2 3.2 0 4.6-2.8 5.6-5.5 5.9.4.4.8 1.1.8 2.2v3.3c0 .3.2.7.8.6A12 12 0 0 0 16 4Z"
    />
  </svg>
);

const GitLab = ({ className }: LogoProps) => (
  <svg viewBox="0 0 32 32" className={className} aria-hidden>
    <path d="M16 28 5 16l2-9 4 9h10l4-9 2 9-11 12Z" fill="#E24329" />
    <path d="M16 28 11 16h10l-5 12Z" fill="#FC6D26" />
    <path d="M16 28 5 16l6-1 5 13Zm0 0 11-12-6-1-5 13Z" fill="#FCA326" />
  </svg>
);

const Bitbucket = ({ className }: LogoProps) => (
  <svg viewBox="0 0 32 32" className={className} aria-hidden>
    <path d="M4 6h24l-3 21H7L4 6Z" fill="#2684FF" />
    <path d="M13 12h6l-1 8h-4l-1-8Z" fill="#fff" />
  </svg>
);

const Webhook = ({ className }: LogoProps) => (
  <svg viewBox="0 0 32 32" className={className} aria-hidden>
    <circle
      cx="11"
      cy="11"
      r="3.5"
      fill="none"
      stroke="#171717"
      strokeWidth="1.5"
    />
    <circle
      cx="22"
      cy="22"
      r="3.5"
      fill="none"
      stroke="#171717"
      strokeWidth="1.5"
    />
    <circle
      cx="10"
      cy="23"
      r="3.5"
      fill="none"
      stroke="#171717"
      strokeWidth="1.5"
    />
    <path
      d="M11 14.5 7 22m6-8 6 9m-6.5 1h7"
      stroke="#171717"
      strokeWidth="1.5"
      fill="none"
      strokeLinecap="round"
    />
  </svg>
);

const S3 = ({ className }: LogoProps) => (
  <svg viewBox="0 0 32 32" className={className} aria-hidden>
    <path d="M16 4 6 7v15c0 3 4.5 6 10 6s10-3 10-6V7L16 4Z" fill="#E25444" />
    <path d="M16 4v24c5.5 0 10-3 10-6V7L16 4Z" fill="#7B1D13" opacity=".55" />
    <text
      x="16"
      y="20"
      textAnchor="middle"
      fontFamily="Inter, system-ui, sans-serif"
      fontWeight="700"
      fontSize="9"
      fill="#fff"
      letterSpacing="0.5"
    >
      S3
    </text>
  </svg>
);

const HackerOne = ({ className }: LogoProps) => (
  <svg viewBox="0 0 32 32" className={className} aria-hidden>
    <path d="M16 3 4 9v14l12 6 12-6V9L16 3Z" fill="#494C50" />
    <text
      x="16"
      y="20.5"
      textAnchor="middle"
      fontFamily="Inter, system-ui, sans-serif"
      fontWeight="800"
      fontSize="11"
      fill="#fff"
    >
      h1
    </text>
  </svg>
);

const Bugcrowd = ({ className }: LogoProps) => (
  <svg viewBox="0 0 32 32" className={className} aria-hidden>
    <path d="M16 3 28 10v12L16 29 4 22V10L16 3Z" fill="#F26822" />
    <circle cx="16" cy="16" r="6" fill="#fff" />
    <circle cx="14" cy="15" r="1.4" fill="#F26822" />
    <circle cx="18" cy="15" r="1.4" fill="#F26822" />
    <path
      d="M13 19c1 1.5 5 1.5 6 0"
      stroke="#F26822"
      strokeWidth="1.4"
      fill="none"
      strokeLinecap="round"
    />
  </svg>
);

const Cobalt = ({ className }: LogoProps) => (
  <svg viewBox="0 0 32 32" className={className} aria-hidden>
    <rect x="3" y="3" width="26" height="26" rx="4" fill="#1D1D3A" />
    <path
      d="M11 13a4 4 0 0 1 4-4h4v3h-4a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h4v3h-4a4 4 0 0 1-4-4v-6Z"
      fill="#9E8EFF"
    />
    <circle cx="22" cy="22" r="2" fill="#9E8EFF" />
  </svg>
);

// Registry: kind → logo component
export const BRAND_LOGOS: Record<string, React.FC<LogoProps>> = {
  slack: Slack,
  teams: Teams,
  google_chat: GoogleChat,
  discord: Discord,
  pagerduty: PagerDuty,
  opsgenie: Opsgenie,
  email: Email,
  splunk: Splunk,
  datadog: Datadog,
  jira: Jira,
  github_issues: GitHub,
  github_status: GitHub,
  gitlab: GitLab,
  bitbucket: Bitbucket,
  webhook: Webhook,
  s3: S3,
  hackerone: HackerOne,
  bugcrowd: Bugcrowd,
  cobalt: Cobalt,
};

// Wrapper: renders the registered logo on a soft tile, falls back to a
// letter glyph if no logo is registered for the given kind.
export function BrandLogo({
  kind,
  size = 40,
  className,
}: {
  kind: string;
  size?: number;
  className?: string;
}) {
  const Logo = BRAND_LOGOS[kind];
  if (Logo) {
    return (
      <span
        className={cn(
          "inline-flex items-center justify-center rounded-md bg-vellum border border-hairline shrink-0",
          className,
        )}
        style={{ width: size, height: size }}
        aria-hidden
      >
        <Logo className="w-[68%] h-[68%]" />
      </span>
    );
  }
  return (
    <span
      className={cn(
        "inline-flex items-center justify-center rounded-md bg-vellum border border-hairline font-display font-bold text-graphite shrink-0 uppercase",
        className,
      )}
      style={{ width: size, height: size, fontSize: size * 0.4 }}
      aria-hidden
    >
      {kind.slice(0, 2)}
    </span>
  );
}

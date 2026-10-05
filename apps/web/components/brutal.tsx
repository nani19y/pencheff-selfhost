"use client";

import * as React from "react";
import { cn } from "@/lib/cn";

/**
 * Pencheff "Sunset Observability" UI primitives.
 * Export names preserved for backward compatibility; the visual
 * language now uses warm paper, Fraunces display, hairline borders,
 * and an ember-orange primary with gilt highlights.
 */

type Variant = "yellow" | "pink" | "cyan" | "lime" | "danger" | "ink" | "gilt";

const BUTTON_BASE =
  "inline-flex items-center justify-center gap-2 rounded-md font-body text-sm font-medium tracking-[0.005em] px-4 py-2.5 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed active:translate-y-px";

const VARIANT_CLASSES: Record<Variant, string> = {
  // Neutral default — paper w/ hairline
  yellow:
    "bg-paper text-graphite border border-hairline shadow-subtle hover:border-ink hover:text-ink hover:shadow-elev active:bg-vellum disabled:hover:border-hairline",
  // Primary — ember (sunset orange)
  pink:
    "bg-orange-400 text-paper border border-orange-500 hover:bg-orange-500 hover:border-orange-600 shadow-[inset_0_1px_0_rgba(255,255,255,0.32),0_8px_20px_-8px_rgba(232,90,6,0.45)] hover:shadow-[inset_0_1px_0_rgba(255,255,255,0.32),0_14px_30px_-12px_rgba(232,90,6,0.6)] font-semibold",
  // Ghost
  cyan: "bg-transparent text-graphite border border-transparent hover:text-ink hover:underline underline-offset-[6px] decoration-gilt decoration-2",
  // Secondary outline — ink ring, fills on hover
  lime:
    "bg-paper text-ink border border-ink shadow-subtle hover:bg-ink hover:text-paper hover:shadow-elev font-semibold",
  // Destructive
  danger:
    "bg-paper text-oxblood border border-oxblood hover:bg-oxblood hover:text-paper",
  // Inverted ink (deepest)
  ink: "bg-ink text-paper border border-ink shadow-subtle hover:bg-dusk font-semibold",
  // Gilt — premium / upgrade accent
  gilt:
    "bg-gold-400 text-ink border border-gold-500 shadow-subtle hover:bg-gold-300 hover:border-gold-400 font-semibold",
};

export const Button = React.forwardRef<
  HTMLButtonElement,
  React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant }
>(({ className, variant = "yellow", ...props }, ref) => (
  <button
    ref={ref}
    className={cn(BUTTON_BASE, VARIANT_CLASSES[variant], className)}
    {...props}
  />
));
Button.displayName = "Button";

export const Card = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      className={cn(
        "bg-paper border border-hairline rounded-lg shadow-subtle p-6",
        className
      )}
      style={{ backgroundImage: "linear-gradient(180deg, var(--parchment) 0%, var(--paper) 35%)" }}
      {...props}
    />
  )
);
Card.displayName = "Card";

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        "bg-paper border border-hairline rounded-md px-3.5 py-2.5",
        "font-body text-[15px] text-graphite w-full placeholder:text-mist",
        "focus:outline-none focus:border-orange-400 focus:ring-2 focus:ring-orange-200",
        "transition-all duration-200",
        className
      )}
      {...props}
    />
  )
);
Input.displayName = "Input";

export function Label({ className, ...props }: React.LabelHTMLAttributes<HTMLLabelElement>) {
  return (
    <label
      className={cn(
        "block font-mono font-medium text-[11px] text-slate uppercase tracking-[0.18em] mb-2",
        className
      )}
      {...props}
    />
  );
}

/**
 * Small hairline pill, used for metadata chips (plan name, status, etc.).
 * `variant` lets callers opt in to sunset-accent fills; default is neutral.
 */
const BADGE_VARIANT: Record<Variant, string> = {
  yellow: "border-hairline bg-paper text-slate",
  pink:   "border-orange-300 bg-orange-50 text-orange-700",
  cyan:   "border-hairline bg-vellum text-graphite",
  lime:   "border-forest/30 bg-forest/5 text-forest",
  danger: "border-oxblood/40 bg-oxblood/5 text-oxblood",
  ink:    "border-ink bg-ink text-paper",
  gilt:   "border-gold-300 bg-gold-50 text-gold-700",
};

export function Badge({
  className,
  variant = "yellow",
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & { variant?: Variant }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 border",
        "rounded-sm px-2 py-0.5 font-mono text-[10.5px] font-medium uppercase tracking-[0.16em]",
        BADGE_VARIANT[variant],
        className
      )}
      {...props}
    />
  );
}

const SEVERITY_BAR: Record<string, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

const SEVERITY_LABEL: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Informational",
};

/**
 * Editorial severity indicator — a 3 px vertical bar (bookmark metaphor)
 * plus a small-caps label. Renders as a single inline element so every
 * existing caller works unchanged.
 */
export function SeverityPill({ severity }: { severity: string }) {
  const s = (severity || "info").toLowerCase();
  const bar = SEVERITY_BAR[s] || SEVERITY_BAR.info;
  const label = SEVERITY_LABEL[s] || s;
  return (
    <span className="inline-flex items-center gap-2 whitespace-nowrap">
      <span className={cn("inline-block w-[3px] h-[14px] rounded-[1px]", bar)} />
      <span className="font-body text-[11px] font-medium uppercase tracking-[0.18em] text-slate">
        {label}
      </span>
    </span>
  );
}

const GRADE_RING: Record<string, string> = {
  A: "text-forest border-forest",
  B: "text-sev-low border-sev-low",
  C: "text-sev-medium border-sev-medium",
  D: "text-sev-high border-sev-high",
  F: "text-oxblood border-oxblood",
};

/**
 * Editorial "seal" grade badge — double-hairline circle with a serif letter
 * and a small-caps "Grade" eyebrow above.
 */
export function GradeBadge({
  grade,
  size = "md",
}: {
  grade?: string | null;
  size?: "sm" | "md" | "lg";
}) {
  const g = (grade || "-").toUpperCase();
  const ring = GRADE_RING[g] || "text-slate border-hairline";
  const dims =
    size === "lg"
      ? "w-32 h-32 text-[72px]"
      : size === "sm"
      ? "w-14 h-14 text-[28px]"
      : "w-20 h-20 text-[44px]";
  const eyebrowSize =
    size === "lg" ? "text-[11px] mb-3" : size === "sm" ? "text-[9px] mb-1" : "text-[10px] mb-2";

  return (
    <div className="inline-flex flex-col items-center">
      <span className={cn("eyebrow-gilt", eyebrowSize)}>Grade</span>
      <span
        className={cn(
          "relative inline-flex items-center justify-center rounded-full",
          "border-2 bg-paper shadow-elev",
          dims,
          ring
        )}
        style={{
          backgroundImage:
            "radial-gradient(circle at 30% 25%, rgba(255,226,196,0.55) 0%, rgba(255,255,255,0) 60%)",
        }}
      >
        <span
          className={cn(
            "absolute inset-[6px] rounded-full border border-current opacity-50 pointer-events-none"
          )}
        />
        <span className="relative font-display font-medium leading-none">{g}</span>
      </span>
    </div>
  );
}

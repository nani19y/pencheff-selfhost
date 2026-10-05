/**
 * Canonical pricing + plan-quota constants. Single source of truth for every
 * pricing/billing surface (marketing /pricing, landing tiers, in-app /billing).
 *
 * Keep these in sync with the backend:
 *   - apps/api/.../services/quota.py        → scans_per_month_per_org
 *   - apps/api/.../services/fix_quota.py    → FIX_LIMITS
 */

export type PlanId = "free" | "pro" | "team";

/** Pro plan price. USD is the displayed price; INR kept for the Razorpay
 * region reference. NOTE: display only — the actual charge is the Razorpay
 * plan ID (RAZORPAY_PLAN_PRO_USD/INR), which must match when billing goes live. */
export const PRO_PRICE = { inr: 499, usd: 4.99 } as const;

/** Enterprise plan price (displayed; CTA is contact-sales, not in-app checkout). */
export const ENTERPRISE_PRICE = { usd: 499 } as const;

/** Per-plan monthly quotas, mirroring the backend caps. */
export const PLAN_QUOTAS = {
  free: { scans: 5, fixes: 3, model: "Instant" },
  pro: { scans: 20, fixes: 40, model: "Expert" },
} as const;

/** "₹499" */
export function inr(amount: number): string {
  return `₹${amount.toLocaleString("en-IN")}`;
}

/** "$5.99" (drops the decimals for whole amounts). */
export function usd(amount: number): string {
  return `$${Number.isInteger(amount) ? amount : amount.toFixed(2)}`;
}

/** "₹499 / $5.99" — dual-currency label, INR first. */
export function dualPrice(p: { inr: number; usd: number } = PRO_PRICE): string {
  return `${inr(p.inr)} / ${usd(p.usd)}`;
}

/** Canonical Pro price label used across all pricing surfaces. */
export const PRO_PRICE_LABEL = dualPrice(PRO_PRICE);

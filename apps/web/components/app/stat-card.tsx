import { cn } from "@/lib/cn";

interface StatCardProps {
  label: string;
  value: string | number;
  sub?: string;
  highlight?: "gilt" | "red" | "green";
  className?: string;
}

export function StatCard({ label, value, sub, highlight, className }: StatCardProps) {
  return (
    <div className={cn("flex flex-col gap-1 border border-hairline rounded-sm bg-paper px-4 py-3 min-w-0", className)}>
      <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-mist">{label}</span>
      <span
        className={cn(
          "font-display text-[28px] leading-none tracking-[-0.02em]",
          highlight === "gilt" ? "text-gilt" :
          highlight === "red" ? "text-sev-critical" :
          highlight === "green" ? "text-forest" :
          "text-ink"
        )}
      >
        {value}
      </span>
      {sub && (
        <span className="font-mono text-[11px] text-mist mt-0.5">{sub}</span>
      )}
    </div>
  );
}

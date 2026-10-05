import { cn } from "@/lib/cn";

interface IntelPanelProps {
  title: string;
  eyebrow?: string;
  children: React.ReactNode;
  className?: string;
}

export function IntelPanel({ title, eyebrow, children, className }: IntelPanelProps) {
  return (
    <div className={cn("space-y-4", className)}>
      <div>
        {eyebrow && (
          <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-gilt mb-1">{eyebrow}</p>
        )}
        <h3 className="font-display text-[16px] text-ink">{title}</h3>
      </div>
      {children}
    </div>
  );
}

interface IntelRowProps {
  label: string;
  value: string | number;
  bar?: number; // 0–100 percent fill
  color?: string; // tailwind bg class
}

export function IntelRow({ label, value, bar, color = "bg-gilt" }: IntelRowProps) {
  return (
    <div className="space-y-1">
      <div className="flex items-baseline justify-between gap-2">
        <span className="font-body text-[12px] text-slate truncate">{label}</span>
        <span className="font-mono text-[12px] text-ink shrink-0">{value}</span>
      </div>
      {bar !== undefined && (
        <div className="h-[3px] w-full bg-vellum rounded-full overflow-hidden">
          <div
            className={cn("h-full rounded-full transition-all", color)}
            style={{ width: `${Math.min(100, Math.max(0, bar))}%` }}
          />
        </div>
      )}
    </div>
  );
}

interface IntelDividerProps {
  label: string;
}

export function IntelDivider({ label }: IntelDividerProps) {
  return (
    <div className="flex items-center gap-2 pt-2">
      <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-mist whitespace-nowrap">{label}</span>
      <div className="flex-1 h-px bg-hairline" />
    </div>
  );
}

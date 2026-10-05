import { cn } from "@/lib/cn";

export function Spinner({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        "h-5 w-5 rounded-full border-2 border-hairline border-t-ink animate-spin",
        className
      )}
      aria-hidden
    />
  );
}

export function Skeleton({ className }: { className?: string }) {
  return (
    <div
      className={cn("animate-pulse rounded-sm bg-vellum/70 border border-hairline", className)}
      aria-hidden
    />
  );
}

export function PageLoading({
  title,
  lines = 2,
  cards = 6,
}: {
  title?: string;
  lines?: number;
  cards?: number;
}) {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-6">
        <div className="min-w-0 flex-1 space-y-3">
          <div className="flex items-center gap-3">
            <Spinner />
            <p className="font-body text-[13px] text-slate tracking-[0.06em] uppercase">
              {title ?? "Loading"}
            </p>
          </div>
          <Skeleton className="h-10 w-[360px] max-w-full" />
          <div className="space-y-2">
            {Array.from({ length: Math.max(0, lines) }).map((_, i) => (
              <Skeleton key={i} className={cn("h-3", i === 0 ? "w-[520px]" : "w-[420px]")} />
            ))}
          </div>
        </div>
        <Skeleton className="h-9 w-[160px] hidden sm:block" />
      </div>
      <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {Array.from({ length: Math.max(0, cards) }).map((_, i) => (
          <Skeleton key={i} className="h-[132px]" />
        ))}
      </div>
    </div>
  );
}

export function InlineLoading({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 text-slate">
      <Spinner className="h-4 w-4 border-2" />
      <span className="text-[13px] italic">{label ?? "Loading…"}</span>
    </div>
  );
}


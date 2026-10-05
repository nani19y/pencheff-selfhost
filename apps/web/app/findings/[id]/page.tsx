"use client";

/**
 * Detail-by-id redirect — the unified findings list links here with
 * just the finding id. We fetch the finding to discover its scan_id,
 * then forward to the canonical ``/scans/[id]/findings/[fid]`` detail
 * page (where the rich UI already lives).
 */

import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { pathSegment } from "@/lib/route-params";
import { api, ApiError } from "@/lib/api";
import { InlineLoading } from "@/components/loading";

export default function FindingDetailRedirect() {
  const pathname = usePathname();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const id = mounted ? pathSegment(pathname, 2) : "";
  const router = useRouter();
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    let alive = true;
    api<{ scan_id: string }>(`/findings/${id}`)
      .then((f) => {
        if (!alive) return;
        router.replace(`/scans/${f.scan_id}/findings/${id}`);
      })
      .catch((e: any) => {
        if (!alive) return;
        if (e instanceof ApiError && e.status === 404) {
          setErr(
            "Finding not found in this workspace. It may belong to a " +
              "different scan kind — try the repo finding detail.",
          );
        } else {
          setErr(e?.message || "Could not load finding.");
        }
      });
    return () => {
      alive = false;
    };
  }, [id, router]);

  return (
    <div className="mx-auto max-w-[640px] py-8 text-center">
      {err ? (
        <div className="space-y-3">
          <p className="font-body text-[14px] text-oxblood">{err}</p>
          <a
            href="/findings"
            className="font-mono text-[12px] text-mist underline hover:text-ink"
          >
            ← Back to all findings
          </a>
        </div>
      ) : (
        <div className="flex justify-center">
          <InlineLoading label="Loading finding…" />
        </div>
      )}
    </div>
  );
}

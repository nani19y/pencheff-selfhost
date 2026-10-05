"use client";

// Phase 4.2 UI — "Verify with humans" button.
//
// Surfaced on every finding card. Posts to one of the Phase 1.2
// partner integration kinds (hackerone / bugcrowd / cobalt). The
// triager's verdict comes back asynchronously via the Phase 4.2
// callback endpoint and flips the finding's verification_status.

import { useState } from "react";
import { Button } from "@/components/brutal";
import { api } from "@/lib/api";

type Kind = "hackerone" | "bugcrowd" | "cobalt";

const KIND_LABEL: Record<Kind, string> = {
  hackerone: "HackerOne",
  bugcrowd: "Bugcrowd",
  cobalt: "Cobalt",
};

type Ack = {
  ok: boolean;
  integration_kind: string;
  submission_url: string | null;
  error: string | null;
};

export function VerifyWithHumansButton({
  findingId,
}: {
  findingId: string;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [ack, setAck] = useState<Ack | null>(null);

  async function submit(kind: Kind) {
    setBusy(true);
    setAck(null);
    try {
      const r = await api<Ack>(`/findings/${findingId}/verify-with-humans`, {
        method: "POST",
        json: { integration_kind: kind },
      });
      setAck(r);
    } catch (e: unknown) {
      const msg =
        typeof e === "object" && e && "message" in e
          ? String((e as { message: unknown }).message)
          : String(e);
      setAck({
        ok: false,
        integration_kind: kind,
        submission_url: null,
        error: msg,
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="inline-flex flex-col gap-2">
      {!open ? (
        <Button
          variant="lime"
          onClick={() => setOpen(true)}
          className="text-[12px] px-3 py-1.5"
        >
          Verify with humans →
        </Button>
      ) : (
        <div className="border border-hairline bg-paper p-3 rounded-sm space-y-2 text-[12px]">
          <p className="font-mono text-mist">
            Submit this finding for human triage on…
          </p>
          <div className="flex flex-wrap gap-2">
            {(["hackerone", "bugcrowd", "cobalt"] as Kind[]).map((k) => (
              <Button
                key={k}
                variant="lime"
                disabled={busy}
                onClick={() => submit(k)}
                className="text-[11px] px-2 py-1"
              >
                {KIND_LABEL[k]}
              </Button>
            ))}
            <Button
              variant="cyan"
              onClick={() => {
                setOpen(false);
                setAck(null);
              }}
              className="text-[11px] px-2 py-1"
            >
              Cancel
            </Button>
          </div>
          {ack && (
            <p
              className={
                ack.ok
                  ? "text-forest text-[11px]"
                  : "text-oxblood text-[11px]"
              }
            >
              {ack.ok
                ? `Submitted to ${KIND_LABEL[ack.integration_kind as Kind]}. The triager's verdict will flip this finding's status when it arrives.`
                : `${ack.error || "submission failed"}`}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

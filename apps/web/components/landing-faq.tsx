"use client";

import { useState } from "react";
import { LANDING_FAQ } from "@/lib/landing-faq";

function pad(n: number) {
  return n.toString().padStart(2, "0");
}

export function LandingFAQ() {
  const [open, setOpen] = useState<Set<number>>(() => new Set([0]));

  const toggle = (i: number) => {
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i);
      else next.add(i);
      return next;
    });
  };

  return (
    <div className="lp-faq-list">
      {LANDING_FAQ.map((f, i) => {
        const isOpen = open.has(i);
        return (
          <div
            key={f.q}
            className={`lp-faq-item${isOpen ? " lp-open" : ""}`}
          >
            <button
              type="button"
              className="lp-faq-q"
              aria-expanded={isOpen}
              onClick={() => toggle(i)}
            >
              <span className="lp-qnum">№ {pad(i + 1)}</span>
              <span className="lp-qtext">{f.q}</span>
              <span className="lp-qglyph" aria-hidden>
                +
              </span>
            </button>
            <div className="lp-faq-a" role="region">
              <p className="lp-atext">{f.a}</p>
            </div>
          </div>
        );
      })}
    </div>
  );
}

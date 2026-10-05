"use client";

import { useEffect } from "react";

/**
 * Client-side animations for the landing page:
 *   1. Per-character slide-in on `[data-slide-chars]` headlines (Standout signature).
 *      Words are wrapped in `inline-block; white-space: nowrap` so line breaks
 *      can only happen between words, never inside one.
 *   2. IntersectionObserver-driven reveals on `.lp-fade-up`, `.lp-fade-spring`,
 *      `.lp-slide-chars`, `.lp-phase` — adds `.lp-in` when in view.
 *   3. Number counters on `[data-count-to]` — animate 0 → target on scroll.
 *
 * Mounted once near the top of the landing page; runs in `useEffect` so it's
 * client-only and won't fire during SSR.
 */
export function LandingEffects() {
  useEffect(() => {
    if (typeof window === "undefined") return;

    // ─── 1. Per-character slide split ───
    let charCounter = 0;
    function processTextNode(textNode: Text) {
      const text = textNode.nodeValue ?? "";
      if (!text || text.replace(/\s/g, "") === "") return;
      const frag = document.createDocumentFragment();
      const parts = text.split(/(\s+)/);
      parts.forEach((part) => {
        if (part === "") return;
        if (/^\s+$/.test(part)) {
          frag.appendChild(document.createTextNode(part));
          return;
        }
        const word = document.createElement("span");
        word.className = "word";
        for (const ch of part) {
          const c = document.createElement("span");
          c.className = "char";
          c.textContent = ch;
          c.style.setProperty("--lp-d", `${charCounter++ * 22}ms`);
          word.appendChild(c);
        }
        frag.appendChild(word);
      });
      textNode.parentNode?.replaceChild(frag, textNode);
    }
    function walkAndSplit(el: Element) {
      const kids = Array.from(el.childNodes);
      for (const node of kids) {
        if (node.nodeType === Node.TEXT_NODE) {
          processTextNode(node as Text);
        } else if (node.nodeType === Node.ELEMENT_NODE) {
          const elem = node as Element;
          // Atomic units: don't split into per-character spans. Fraunces
          // italic ligatures and kerning break when each glyph becomes its
          // own inline-block; wrap the whole span in a single .word/.char so
          // it still slides in as part of the line's animation.
          const isAtomic =
            elem.classList?.contains("lp-italic-gilt") ||
            elem.classList?.contains("lp-gilt-italic") ||
            elem.matches?.("[data-no-split]");
          if (isAtomic) {
            const word = document.createElement("span");
            word.className = "word";
            const ch = document.createElement("span");
            ch.className = "char";
            ch.style.setProperty("--lp-d", `${charCounter++ * 22}ms`);
            elem.parentNode?.replaceChild(word, elem);
            ch.appendChild(elem);
            word.appendChild(ch);
            continue;
          }
          // Skip elements that already have `.char` (avoid double-splitting
          // on a fast-refresh remount).
          if (elem.querySelector?.(".char")) continue;
          walkAndSplit(elem);
        }
      }
    }
    const slideTargets = document.querySelectorAll<HTMLElement>(
      "[data-slide-chars]:not(.lp-slide-chars)"
    );
    slideTargets.forEach((el) => {
      walkAndSplit(el);
      el.classList.add("lp-slide-chars");
    });

    // ─── 2. Reveal IntersectionObserver ───
    const reveal = document.querySelectorAll(
      ".lp-fade-up, .lp-fade-spring, .lp-slide-chars, .lp-phase"
    );
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (!e.isIntersecting) return;
          e.target.classList.add("lp-in");
          io.unobserve(e.target);
        });
      },
      { rootMargin: "0px 0px -8% 0px", threshold: 0.05 }
    );
    reveal.forEach((el) => io.observe(el));

    // Hero slide-chars: reveal on load, not on scroll (above-fold).
    function fireHero() {
      document
        .querySelectorAll(".lp-hero .lp-slide-chars")
        .forEach((el) => el.classList.add("lp-in"));
    }
    if (document.readyState === "complete") fireHero();
    else window.addEventListener("load", fireHero, { once: true });

    // ─── 3. Counters ───
    const counters = document.querySelectorAll<HTMLElement>("[data-count-to]");
    const cio = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (!e.isIntersecting) return;
          const el = e.target as HTMLElement;
          const target = parseInt(el.dataset.countTo ?? "0", 10);
          const dur = 1500;
          const start = performance.now();
          function tick(now: number) {
            const t = Math.min(1, (now - start) / dur);
            const eased = 1 - Math.pow(1 - t, 3);
            el.textContent = Math.round(eased * target).toString();
            if (t < 1) requestAnimationFrame(tick);
          }
          requestAnimationFrame(tick);
          cio.unobserve(el);
        });
      },
      { threshold: 0.4 }
    );
    counters.forEach((el) => cio.observe(el));

    // ─── 4. Magnetic CTAs ───
    const magnetic = document.querySelectorAll<HTMLElement>(".lp-btn");
    const cleanups: Array<() => void> = [];
    magnetic.forEach((btn) => {
      if (btn.hasAttribute("disabled") || btn.getAttribute("aria-disabled") === "true") return;
      let raf = 0;
      const onMove = (e: MouseEvent) => {
        const r = btn.getBoundingClientRect();
        const x = e.clientX - r.left - r.width / 2;
        const y = e.clientY - r.top - r.height / 2;
        cancelAnimationFrame(raf);
        raf = requestAnimationFrame(() => {
          btn.style.transform = `translate(${x * 0.18}px, ${y * 0.28}px)`;
        });
      };
      const onLeave = () => {
        cancelAnimationFrame(raf);
        btn.style.transform = "";
      };
      btn.addEventListener("mousemove", onMove);
      btn.addEventListener("mouseleave", onLeave);
      cleanups.push(() => {
        btn.removeEventListener("mousemove", onMove);
        btn.removeEventListener("mouseleave", onLeave);
        cancelAnimationFrame(raf);
      });
    });

    return () => {
      io.disconnect();
      cio.disconnect();
      cleanups.forEach((fn) => fn());
    };
  }, []);

  return null;
}

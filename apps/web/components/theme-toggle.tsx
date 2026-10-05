"use client";

import { useEffect, useState } from "react";

type Theme = "light" | "dark";

/**
 * ThemeToggle — sun/moon button that flips data-theme + .dark on <html>
 * and persists the choice to localStorage. The pre-hydration script in
 * RootLayout reads the stored value (or defaults to dark) before paint,
 * so there's no flash. This component just keeps state in sync with the
 * <html> attribute after hydration.
 *
 * `variant`:
 *   - "landing": pill button used in the landing nav (light bg, hairline).
 *   - "nav":     compact icon button for the logged-in app nav.
 */
export function ThemeToggle({
  variant = "landing",
  className = "",
}: {
  variant?: "landing" | "nav";
  className?: string;
}) {
  const [theme, setTheme] = useState<Theme>("dark");
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    const current =
      (document.documentElement.getAttribute("data-theme") as Theme) ||
      "dark";
    setTheme(current);
  }, []);

  function toggle() {
    const next: Theme = theme === "dark" ? "light" : "dark";
    setTheme(next);
    const root = document.documentElement;
    root.setAttribute("data-theme", next);
    root.classList.toggle("dark", next === "dark");
    root.style.colorScheme = next;
    try {
      localStorage.setItem("pencheff-theme", next);
    } catch {
      // localStorage may be unavailable (Safari private, etc.) — ignore.
    }
  }

  const label = theme === "dark" ? "Switch to light mode" : "Switch to dark mode";
  const isDark = theme === "dark";

  // Render a neutral fallback during SSR / before hydration so the markup
  // matches and there's no hydration mismatch.
  const ariaPressed = mounted ? isDark : undefined;

  if (variant === "nav") {
    return (
      <button
        type="button"
        onClick={toggle}
        aria-label={label}
        title={label}
        aria-pressed={ariaPressed}
        className={
          "app-theme-toggle inline-flex items-center justify-center " +
          "shrink-0 grow-0 w-10 h-10 rounded-lg " +
          "border border-hairline bg-paper text-graphite " +
          "hover:border-orange-400 hover:text-orange-500 hover:shadow-elev " +
          "transition-all duration-200 " +
          className
        }
        style={{
          minWidth: 40,
          minHeight: 40,
          aspectRatio: "1 / 1",
          padding: 0,
        }}
      >
        <ThemeIcon isDark={isDark} />
      </button>
    );
  }

  // "landing" pill — sits in the marketing nav alongside Open-app CTA.
  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={label}
      title={label}
      aria-pressed={ariaPressed}
      className={
        "lp-theme-toggle inline-flex items-center justify-center " +
        "shrink-0 w-10 h-10 rounded-lg transition-all duration-200 " +
        className
      }
    >
      <ThemeIcon isDark={isDark} />
    </button>
  );
}

function ThemeIcon({ isDark }: { isDark: boolean }) {
  return isDark ? (
    // Sun (shown when dark — clicking switches to light)
    <svg
      width="17"
      height="17"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
    </svg>
  ) : (
    // Moon (shown when light — clicking switches to dark)
    <svg
      width="17"
      height="17"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
    </svg>
  );
}

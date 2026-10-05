import { useEffect, useState } from "react";

type Theme = "light" | "dark";

/**
 * DocsThemeToggle — sun/moon button placed in Nextra's navbar.extraContent.
 * Nextra's built-in toggle lives in the (collapsed) sidebar footer, so on
 * the docs homepage it isn't visible. This adds an always-visible top-nav
 * toggle that flips `localStorage.theme` + the `.dark` class on <html> —
 * exactly what Nextra's next-themes wrapper reads.
 */
export default function DocsThemeToggle() {
  const [theme, setTheme] = useState<Theme>("dark");
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    const isDark = document.documentElement.classList.contains("dark");
    setTheme(isDark ? "dark" : "light");
  }, []);

  function toggle() {
    const next: Theme = theme === "dark" ? "light" : "dark";
    setTheme(next);
    const root = document.documentElement;
    root.classList.toggle("dark", next === "dark");
    root.style.colorScheme = next;
    try {
      localStorage.setItem("theme", next);
    } catch {
      /* ignore */
    }
  }

  const label =
    theme === "dark" ? "Switch to light mode" : "Switch to dark mode";
  const isDark = theme === "dark";

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={label}
      title={label}
      aria-pressed={mounted ? isDark : undefined}
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        width: 34,
        height: 34,
        marginLeft: 10,
        background: "transparent",
        border: "1px solid rgba(232,220,198,0.18)",
        borderRadius: 8,
        color: "#E8DCC6",
        cursor: "pointer",
        transition: "background 0.2s, border-color 0.2s, color 0.2s",
      }}
      onMouseEnter={(e) => {
        (e.currentTarget as HTMLButtonElement).style.background =
          "rgba(251,122,28,0.08)";
        (e.currentTarget as HTMLButtonElement).style.borderColor = "#FB7A1C";
        (e.currentTarget as HTMLButtonElement).style.color = "#FFA158";
      }}
      onMouseLeave={(e) => {
        (e.currentTarget as HTMLButtonElement).style.background = "transparent";
        (e.currentTarget as HTMLButtonElement).style.borderColor =
          "rgba(232,220,198,0.18)";
        (e.currentTarget as HTMLButtonElement).style.color = "#E8DCC6";
      }}
    >
      {isDark ? (
        <svg
          width="16"
          height="16"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.7"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden
        >
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
        </svg>
      ) : (
        <svg
          width="16"
          height="16"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.7"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden
        >
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
        </svg>
      )}
    </button>
  );
}

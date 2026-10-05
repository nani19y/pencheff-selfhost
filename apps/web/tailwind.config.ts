import type { Config } from "tailwindcss";
// eslint-disable-next-line @typescript-eslint/no-var-requires
const flattenColorPalette =
  require("tailwindcss/lib/util/flattenColorPalette").default;

/**
 * Pencheff — "Sunset Observability" palette.
 * Warm paper, warm ink, ember orange brand, champagne→amber gilt.
 * Inspired by New Relic dashboard clarity at golden hour.
 */
const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      animation: {
        aurora: "aurora 60s linear infinite",
        "ember-drift": "ember-drift 28s ease-in-out infinite",
        "sun-rise": "sun-rise 1.4s cubic-bezier(.22,.61,.36,1) both",
      },
      keyframes: {
        aurora: {
          from: { backgroundPosition: "50% 50%, 50% 50%" },
          to:   { backgroundPosition: "350% 50%, 350% 50%" },
        },
        "ember-drift": {
          "0%, 100%": { transform: "translate(0,0) scale(1)", opacity: "0.55" },
          "50%":      { transform: "translate(2vw,-2vw) scale(1.06)", opacity: "0.7" },
        },
        "sun-rise": {
          from: { opacity: "0", transform: "translateY(20px)" },
          to:   { opacity: "1", transform: "translateY(0)" },
        },
      },
      colors: {
        // ── Ink scale (pure neutral grayscale) ──
        ink:        "#000000",   // pure black, used for headings + brand mark
        graphite:   "#171717",   // body text default
        slate:      "#525252",   // secondary text, captions
        mist:       "#A3A3A3",   // tertiary, placeholders
        hairline:   "#E5E5E5",   // rules, borders, dividers
        canvas:     "#FFFFFF",   // base page background
        paper:      "#FFFFFF",   // card/foreground surface (same value, semantic)
        vellum:     "#FAFAFA",   // raised neutral surface
        parchment:  "#F5F5F5",   // very subtle neutral wash
        dusk:       "#0A0A0A",   // deep almost-black, for dark sections

        // ── Orange scale (50 = palest sunrise wash, 900 = deepest ember) ──
        orange: {
          50:  "#FFF6EE",
          100: "#FFE6D1",
          200: "#FFC79A",
          300: "#FFA158",
          400: "#FB7A1C",   // primary action default
          500: "#E85A06",   // primary action hover / strong accent
          600: "#C44805",   // pressed / deep accent
          700: "#9A3604",
          800: "#6B2302",
          900: "#3D1201",
        },
        ember: {
          // Semantic aliases for the brand-orange gradient stops
          light:  "#FFA158",
          DEFAULT:"#FB7A1C",
          deep:   "#E85A06",
          dark:   "#9A3604",
        },

        // ── Gold scale (50 = champagne, 800 = dark amber) ──
        gold: {
          50:  "#FFFBED",
          100: "#FFF2C7",
          200: "#F8DD85",
          300: "#E5BD63",
          400: "#C9A24E",   // gilt — primary highlight
          500: "#A8843A",
          600: "#8A6A2A",
          700: "#665022",
          800: "#473814",
        },
        // Legacy gilt aliases (don't break existing markup). Routed through a
        // CSS variable so dark mode can lift to a brighter champagne without
        // touching light mode.
        gilt:  "rgb(var(--gilt-rgb) / <alpha-value>)",
        gilt2: "#8A6A2A",

        // ── Sunset accents ──
        coral:    "#F5C2A6",
        coralInk: "#5A2410",
        lime:     "#D9E27A",
        limeInk:  "#3A4213",
        // Red + green route through CSS variables so dark mode can lift them
        // without disturbing light mode. Channels are defined in globals.css
        // (--oxblood-rgb, --forest-rgb).
        oxblood:  "rgb(var(--oxblood-rgb) / <alpha-value>)",
        forest:   "rgb(var(--forest-rgb) / <alpha-value>)",
        sky:      "#9DB7C9",

        // ── Severity (sunset-tinted) ──
        sev: {
          critical: "rgb(var(--sev-critical-rgb) / <alpha-value>)",  // oxblood, themable
          high:     "#C44805",  // orange-600
          medium:   "#A8843A",  // gold-500
          low:      "#3F6486",  // dusk blue (only cool tone)
          info:     "#6B5E47",  // slate
        },
      },

      boxShadow: {
        // Warm shadows tinted with sunset
        subtle: "0 1px 2px rgba(60,30,8,0.05), 0 1px 1px rgba(60,30,8,0.03)",
        elev:   "0 8px 24px -12px rgba(60,30,8,0.18), 0 2px 6px -2px rgba(60,30,8,0.08)",
        report: "0 24px 60px -30px rgba(60,30,8,0.28), 0 4px 16px -4px rgba(60,30,8,0.10)",
        ember:  "0 18px 60px -24px rgba(232,90,6,0.32), 0 4px 12px -4px rgba(232,90,6,0.18)",
        gilt:   "0 12px 40px -16px rgba(201,162,78,0.45)",
        inset:  "inset 0 1px 0 rgba(255,255,255,0.45), inset 0 -1px 0 rgba(60,30,8,0.04)",
      },

      backgroundImage: {
        "sunset-h":   "linear-gradient(90deg, #FFE6D1 0%, #FFA158 38%, #E85A06 70%, #7A1F1F 100%)",
        "sunset-v":   "linear-gradient(180deg, #FFFBED 0%, #FFE6D1 35%, #FFA158 70%, #E85A06 100%)",
        "sunset-soft":"linear-gradient(135deg, #FDF8EF 0%, #FFF2C7 40%, #FFE6D1 80%, #FFC79A 100%)",
        "horizon":    "radial-gradient(ellipse at bottom, #FB7A1C 0%, #FFA158 25%, #FFE6D1 55%, #FFFFFF 80%)",
        "ember-wash": "radial-gradient(ellipse at 50% 0%, rgba(251,122,28,0.12) 0%, rgba(251,122,28,0) 60%)",
        "paper-grain":
          "url(\"data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='220' height='220'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='0.92' numOctaves='2' stitchTiles='stitch'/><feColorMatrix values='0 0 0 0 0.08  0 0 0 0 0.05  0 0 0 0 0.02  0 0 0 0.55 0'/></filter><rect width='100%' height='100%' filter='url(%23n)'/></svg>\")",
        "gilt-rule":  "linear-gradient(90deg, transparent 0%, #C9A24E 30%, #C9A24E 70%, transparent 100%)",
      },

      borderWidth: {
        "0.5": "0.5px",
        "3":   "3px",
      },
      borderRadius: {
        sm:      "3px",
        DEFAULT: "5px",
        md:      "7px",
        lg:      "10px",
        xl:      "14px",
        "2xl":   "20px",
      },
      fontFamily: {
        // Display: Clash Display — bold geometric, contemporary
        display: ["Clash Display", "PP Neue Montreal", "system-ui", "sans-serif"],
        // Body: Satoshi — clean Swiss-inspired sans
        body:    ["Satoshi", "Söhne", "Inter", "system-ui", "sans-serif"],
        // Mono: JetBrains Mono — for code, IDs, metrics
        mono:    ["'JetBrains Mono'", "Geist Mono", "ui-monospace", "monospace"],
      },
      letterSpacing: {
        eyebrow: "0.18em",
        wider2:  "0.22em",
        tight2:  "-0.022em",
      },
      fontSize: {
        // Editorial display sizes
        "display-1": ["clamp(56px, 7vw, 112px)", { lineHeight: "0.98", letterSpacing: "-0.032em" }],
        "display-2": ["clamp(40px, 5.6vw, 80px)", { lineHeight: "1.02", letterSpacing: "-0.028em" }],
        "display-3": ["clamp(28px, 3.4vw, 48px)", { lineHeight: "1.08", letterSpacing: "-0.022em" }],
        eyebrow:     ["11px", { lineHeight: "1", letterSpacing: "0.18em" }],
      },
    },
  },
  plugins: [addVariablesForColors],
};

// Expose every Tailwind color as a CSS variable (e.g. var(--orange-500)) so
// the AuroraBackground and other components reading inline custom properties
// resolve correctly.
function addVariablesForColors({ addBase, theme }: any) {
  const allColors = flattenColorPalette(theme("colors"));
  const newVars = Object.fromEntries(
    Object.entries(allColors).map(([key, val]) => [`--${key}`, val]),
  );

  addBase({ ":root": newVars });
}

export default config;

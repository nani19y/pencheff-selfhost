import type { Metadata } from "next";
import "./globals.css";
import "highlight.js/styles/atom-one-light.css";
import { ThemeToggle } from "./theme-toggle";

const LANDING_URL =
  process.env.NEXT_PUBLIC_LANDING_URL || "https://pencheff.com";

export const metadata: Metadata = {
  title: {
    default: "Pencheff Blog",
    template: "%s | Pencheff Blog",
  },
  description:
    "Insights on AI-native penetration testing, security research, and product updates from the Pencheff team.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" data-theme="dark" className="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          rel="preconnect"
          href="https://fonts.gstatic.com"
          crossOrigin="anonymous"
        />
        {/* Pre-hydration theme init — apply stored preference (or default
          *  dark) before first paint. */}
        <script
          dangerouslySetInnerHTML={{
            __html: `
              try {
                var t = localStorage.getItem('pencheff-theme') || 'dark';
                var r = document.documentElement;
                r.setAttribute('data-theme', t);
                r.classList.toggle('dark', t === 'dark');
                r.style.colorScheme = t;
              } catch (e) {}
            `,
          }}
        />
      </head>
      <body>
        <header className="blog-header">
          <nav className="blog-nav">
            <a href="/" className="blog-logo">
              Pencheff Blog
            </a>
            <div className="blog-nav-right">
              <ThemeToggle />
              <a href={LANDING_URL} className="blog-back-link">
                pencheff.com
              </a>
            </div>
          </nav>
        </header>
        <main className="blog-main">{children}</main>
        <footer className="blog-footer">
          <p>
            © {new Date().getFullYear()} Pencheff ·{" "}
            <a href={LANDING_URL}>pencheff.com</a>
          </p>
        </footer>
      </body>
    </html>
  );
}

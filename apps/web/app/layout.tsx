import "../styles/globals.css";
import type { Metadata, Viewport } from "next";
import { AppClerkProvider } from "@/components/clerk-provider";
import { WorkspaceProvider } from "@/lib/workspace-context";
import { NotificationsProvider } from "@/lib/notifications-context";
import {
  DEFAULT_DESCRIPTION,
  DEFAULT_TITLE,
  SEO_KEYWORDS,
  SITE_NAME,
  SITE_URL,
  indexableRobots,
} from "@/lib/seo";

const googleVerification = process.env.NEXT_PUBLIC_GOOGLE_SITE_VERIFICATION;

export const metadata: Metadata = {
  metadataBase: SITE_URL,
  applicationName: SITE_NAME,
  title: {
    default: DEFAULT_TITLE,
    template: `%s | ${SITE_NAME}`,
  },
  description: DEFAULT_DESCRIPTION,
  keywords: SEO_KEYWORDS,
  authors: [{ name: "Pencheff", url: SITE_URL }],
  creator: "Pencheff",
  publisher: "Pencheff",
  category: "technology",
  alternates: {
    canonical: "/",
  },
  manifest: "/manifest.webmanifest",
  icons: {
    icon: [
      { url: "/icon-32.png", type: "image/png", sizes: "32x32" },
      { url: "/icon-64.png", type: "image/png", sizes: "64x64" },
      { url: "/icon-192.png", type: "image/png", sizes: "192x192" },
    ],
    shortcut: "/icon-64.png",
    apple: { url: "/apple-icon.png", sizes: "180x180" },
  },
  appleWebApp: {
    capable: true,
    title: SITE_NAME,
    statusBarStyle: "black-translucent",
  },
  formatDetection: {
    telephone: false,
  },
  robots: indexableRobots,
  verification: googleVerification
    ? {
        google: googleVerification,
      }
    : undefined,
  openGraph: {
    type: "website",
    siteName: SITE_NAME,
    locale: "en_US",
    title: DEFAULT_TITLE,
    description: DEFAULT_DESCRIPTION,
    url: "/",
    images: [{ url: "/og.png", width: 1200, height: 630 }],
  },
  twitter: {
    card: "summary_large_image",
    title: DEFAULT_TITLE,
    description: DEFAULT_DESCRIPTION,
    images: ["/og.png"],
  },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 5,
  viewportFit: "cover",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <AppClerkProvider>
      <html lang="en" data-theme="dark" className="dark">
        <head>
          <link rel="preconnect" href="https://fonts.googleapis.com" />
          <link
            rel="preconnect"
            href="https://fonts.gstatic.com"
            crossOrigin="anonymous"
          />
          <link
            rel="preconnect"
            href="https://api.fontshare.com"
            crossOrigin="anonymous"
          />
          <link
            rel="stylesheet"
            href="https://api.fontshare.com/v2/css?f[]=clash-display@500,600,700&f[]=satoshi@300,400,500,700&display=swap"
          />
          {/* Pre-hydration theme init — reads stored preference and applies
           *  data-theme/class on <html> before first paint so there is no
           *  light-flash for users who picked dark, or dark-flash for
           *  users who picked light. Default = dark. */}
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
        <body className="min-h-screen antialiased bg-canvas text-graphite font-body selection:bg-orange-400 selection:text-paper">
          <WorkspaceProvider>
            <NotificationsProvider>{children}</NotificationsProvider>
          </WorkspaceProvider>
        </body>
      </html>
    </AppClerkProvider>
  );
}

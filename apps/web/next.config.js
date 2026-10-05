/** @type {import('next').NextConfig} */
const nextConfig = {
  // Community edition runs as a Next.js server (`next start`) so per-resource
  // dynamic routes (/scans/[id], /findings/[id], …) render on demand. The
  // upstream `output: "export"` was Cloudflare-Pages-specific and cannot serve
  // runtime ids without the Pages _redirects shell rewrites.
  images: { unoptimized: true },
};

module.exports = nextConfig;

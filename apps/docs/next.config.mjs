import nextra from "nextra";

const withNextra = nextra({
  theme: "nextra-theme-docs",
  themeConfig: "./theme.config.tsx",
  defaultShowCopyCode: true,
});

export default withNextra({
  reactStrictMode: true,
  // When deployed to docs.pencheff.com the asset prefix is unchanged.
  // For static export via Cloudflare Pages you can uncomment:
  //   output: 'export',
  //   trailingSlash: true,
});

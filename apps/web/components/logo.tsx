import Image from "next/image";

/**
 * Brand mark rendered from ``/public/logo.png``.
 *
 * Single source of truth — the app nav, the marketing nav, and the
 * favicon all reference this file. Swap the image on disk to update the
 * entire product.
 *
 * The asset is a transparent PNG of the "P" square seal on a square
 * canvas with ~16% built-in padding. We intentionally don't crop here:
 * the padding gives the mark breathing room in every placement.
 */
export function LogoMark({
  size = 32,
  priority = false,
  className,
}: {
  size?: number;
  priority?: boolean;
  className?: string;
}) {
  return (
    <Image
      src="/logo.png"
      alt="Pencheff"
      // Logo asset is 482×512 — keep its aspect so the shield isn't squished.
      width={Math.round((size * 482) / 512)}
      height={size}
      priority={priority}
      className={className}
      // Disable next/image optimisation for the logo — it's a small,
      // pre-sized asset that compresses better shipped as-is than via
      // on-the-fly WebP conversion.
      unoptimized
    />
  );
}

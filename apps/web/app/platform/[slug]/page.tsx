import {
  getMarketingDetailMetadata,
  getMarketingStaticParams,
  MarketingDetailPage,
} from "@/components/marketing-detail-page";
import "@/styles/landing.css";

const MENU = "platform";

// Slugs with a dedicated, hand-built page under app/platform/<slug>/. In
// `output: export` the dynamic [slug] route clobbers the static segment's
// output, so exclude these here to let the bespoke page own the route.
const DEDICATED_SLUGS = new Set(["the-adversarial-cycle"]);

export function generateStaticParams() {
  return getMarketingStaticParams(MENU).filter(
    (p) => !DEDICATED_SLUGS.has(p.slug),
  );
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  return getMarketingDetailMetadata(MENU, slug);
}

export default async function PlatformDetailRoute({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  return <MarketingDetailPage menuSlug={MENU} slug={slug} />;
}

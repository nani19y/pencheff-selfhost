import {
  getMarketingDetailMetadata,
  getMarketingStaticParams,
  MarketingDetailPage,
} from "@/components/marketing-detail-page";
import "@/styles/landing.css";

const MENU = "ai-security";

export function generateStaticParams() {
  return getMarketingStaticParams(MENU);
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  return getMarketingDetailMetadata(MENU, slug);
}

export default async function AiSecurityDetailRoute({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  return <MarketingDetailPage menuSlug={MENU} slug={slug} />;
}

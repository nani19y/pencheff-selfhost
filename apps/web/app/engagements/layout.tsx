import { AuthGuard } from "@/components/auth-guard";
import { privateRouteMetadata } from "@/lib/seo";

export const metadata = privateRouteMetadata;

export default function EngagementsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <AuthGuard>{children}</AuthGuard>;
}

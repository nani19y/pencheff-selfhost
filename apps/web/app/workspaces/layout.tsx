import { AuthGuard } from "@/components/auth-guard";
import { privateRouteMetadata } from "@/lib/seo";

export const metadata = privateRouteMetadata;

export default function WorkspacesLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <AuthGuard>{children}</AuthGuard>;
}

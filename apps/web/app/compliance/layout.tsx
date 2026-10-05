import { AppShell } from "@/components/nav";
import { AuthGuard } from "@/components/auth-guard";
import { privateRouteMetadata } from "@/lib/seo";

export const metadata = privateRouteMetadata;

// ponytail: CE is single-tenant with no plans — compliance is a free KEEP
// feature, so the upstream <EnterpriseGuard> paywall is dropped.
export default function ComplianceLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <AuthGuard>
      <AppShell>
        <main className="max-w-[1400px] mx-auto px-5 md:px-6 py-6">
          {children}
        </main>
      </AppShell>
    </AuthGuard>
  );
}

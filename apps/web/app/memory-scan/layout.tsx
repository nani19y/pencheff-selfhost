import { AppShell } from "@/components/nav";
import { AuthGuard } from "@/components/auth-guard";
import { privateRouteMetadata } from "@/lib/seo";

export const metadata = privateRouteMetadata;

export default function MemoryScanLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <AuthGuard>
      <AppShell>
        <main className="max-w-[1100px] mx-auto px-5 md:px-6 py-6">
          {children}
        </main>
      </AppShell>
    </AuthGuard>
  );
}

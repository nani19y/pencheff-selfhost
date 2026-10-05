import "@/styles/landing.css";
import { LandingNav } from "@/components/landing-nav";
import { LandingEffects } from "@/components/landing-effects";
import { LandingColophon, LandingClosingSection } from "@/components/landing-sections";

export function LandingMarketingPage({
  children,
  closing = true,
}: {
  children: React.ReactNode;
  closing?: boolean;
}) {
  return (
    <div className="landing-root">
      <LandingEffects />
      <LandingNav />
      {children}
      {closing && <LandingClosingSection />}
      <LandingColophon />
    </div>
  );
}


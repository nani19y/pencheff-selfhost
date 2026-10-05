"use client";

import { Input, Label } from "@/components/brutal";
import { FieldHint, SectionIntro } from "./form-helpers";

export type MobilePlatform = "android" | "ios";

const COPY: Record<
  MobilePlatform,
  { eyebrow: string; ext: string; placeholder: string; note: string }
> = {
  android: {
    eyebrow: "Android Application",
    ext: ".apk / .aab",
    placeholder: "https://host/app-release.apk",
    note: "Static analysis only — manifest, exported components, hardcoded secrets, weak crypto, cleartext. The artifact is never installed or executed (no device/emulator).",
  },
  ios: {
    eyebrow: "iOS Application",
    ext: ".ipa",
    placeholder: "https://host/app.ipa",
    note: "Static analysis only — Info.plist/ATS, URL schemes, Mach-O protections, secrets. App-Store IPAs are FairPlay-encrypted, which limits code-level depth. Never executed (no device).",
  },
};

export function MobileAppFormSection({
  platform,
  name,
  setName,
  fileUrl,
  setFileUrl,
  sha256,
  setSha256,
  useMobsf,
  setUseMobsf,
}: {
  platform: MobilePlatform;
  name: string;
  setName: (v: string) => void;
  fileUrl: string;
  setFileUrl: (v: string) => void;
  sha256: string;
  setSha256: (v: string) => void;
  // Android-only MobSF enrichment toggle.
  useMobsf?: boolean;
  setUseMobsf?: (v: boolean) => void;
}) {
  const c = COPY[platform];
  return (
    <div className="space-y-8">
      <section>
        <SectionIntro
          eyebrow={c.eyebrow}
          title={`Point Pencheff at the ${c.ext} artifact`}
          description={c.note}
        />
        <div className="grid gap-5 md:grid-cols-2">
          <div>
            <Label>Name</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={
                platform === "android" ? "My Android app" : "My iOS app"
              }
            />
          </div>
          <div>
            <Label>Artifact URL ({c.ext})</Label>
            <Input
              type="url"
              value={fileUrl}
              onChange={(e) => setFileUrl(e.target.value)}
              placeholder={c.placeholder}
              className="font-mono text-[13px]"
            />
            <FieldHint>Direct HTTPS URL to the build artifact.</FieldHint>
          </div>
          <div className="md:col-span-2">
            <Label>SHA-256</Label>
            <Input
              value={sha256}
              onChange={(e) => setSha256(e.target.value.trim())}
              placeholder="64-char hex digest of the artifact"
              className="font-mono text-[13px]"
            />
            <FieldHint>
              Integrity check — the download is rejected unless its SHA-256
              matches. On macOS/Linux:{" "}
              <code>
                shasum -a 256 app{platform === "android" ? ".apk" : ".ipa"}
              </code>
              .
            </FieldHint>
          </div>
          {platform === "android" && setUseMobsf && (
            <div className="md:col-span-2 flex items-center gap-2">
              <input
                id="mobile-use-mobsf"
                type="checkbox"
                checked={!!useMobsf}
                onChange={(e) => setUseMobsf(e.target.checked)}
              />
              <Label htmlFor="mobile-use-mobsf">
                Enrich with MobSF (requires a MobSF server on the worker)
              </Label>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}

"use client";

import { Input, Label } from "@/components/brutal";
import { FieldHint, SectionIntro } from "./form-helpers";

export type ClientArtifactVariant =
  | "browser_extension"
  | "desktop_app"
  | "firmware"
  | "iot_device"
  | "ot_ics_scada";

const COPY: Record<
  ClientArtifactVariant,
  { eyebrow: string; ext: string; placeholder: string; note: string }
> = {
  browser_extension: {
    eyebrow: "Browser Extension",
    ext: ".crx / .xpi / .zip",
    placeholder: "https://host/extension.crx",
    note: "Static analysis only — manifest permissions, host access, CSP, remote-code loading, DOM sinks, and hardcoded secrets. The extension is never loaded in a browser.",
  },
  desktop_app: {
    eyebrow: "Desktop Application",
    ext: ".zip / .jar / binary",
    placeholder: "https://host/app.zip",
    note: "Static analysis only — Electron webPreferences/fuses, dangerous calls (eval, child_process, shell.openExternal), outdated Electron, and hardcoded secrets. Native binaries get a strings-based secret sweep. Never executed.",
  },
  firmware: {
    eyebrow: "Firmware / Embedded",
    ext: ".bin / .img / archive",
    placeholder: "https://host/firmware.bin",
    note: "Static analysis of a firmware image — embedded private keys & certificates, default/hardcoded credentials, telnet/debug services, cleartext update endpoints, secrets, and component-version banners for CVE matching. Never flashed or executed.",
  },
  iot_device: {
    eyebrow: "IoT Device Firmware",
    ext: ".bin / .img / archive",
    placeholder: "https://host/camera-fw.bin",
    note: "Static firmware analysis for IoT devices — cameras, drones, robot vacuums, routers. Finds embedded keys, default credentials (the Mirai-class compromise vector), insecure services, cleartext endpoints, and vulnerable components. Upload the device's firmware image; the device itself is never touched.",
  },
  ot_ics_scada: {
    eyebrow: "OT / ICS / SCADA Firmware",
    ext: ".bin / .img / archive",
    placeholder: "https://host/plc-firmware.bin",
    note: "Static analysis of controller/PLC firmware or a config export — embedded keys, hardcoded credentials, insecure services, and vulnerable components. Static-only: no active industrial-protocol probing (which can disrupt physical processes).",
  },
};

export function ClientArtifactFormSection({
  variant,
  name,
  setName,
  fileUrl,
  setFileUrl,
  sha256,
  setSha256,
}: {
  variant: ClientArtifactVariant;
  name: string;
  setName: (v: string) => void;
  fileUrl: string;
  setFileUrl: (v: string) => void;
  sha256: string;
  setSha256: (v: string) => void;
}) {
  const c = COPY[variant];
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
              placeholder={`My ${c.eyebrow.toLowerCase()}`}
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
            <FieldHint>Direct HTTPS URL to the artifact.</FieldHint>
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
              matches.
            </FieldHint>
          </div>
        </div>
      </section>
    </div>
  );
}

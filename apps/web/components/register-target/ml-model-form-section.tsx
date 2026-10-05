"use client";

import { Input, Label } from "@/components/brutal";
import { AdvancedSection, FieldHint, SectionIntro } from "./form-helpers";

export type MlSourceType = "file_url" | "huggingface" | "local_path";

export type MlFormatHint =
  | "auto"
  | "pickle"
  | "pytorch"
  | "safetensors"
  | "keras"
  | "h5"
  | "savedmodel"
  | "gguf"
  | "joblib";

const SOURCE_TYPE_OPTIONS: {
  value: MlSourceType;
  label: string;
  body: string;
}[] = [
  {
    value: "file_url",
    label: "File URL",
    body: "Direct HTTP(S) URL to a model artifact (.pkl / .pt / .safetensors / ...)",
  },
  {
    value: "huggingface",
    label: "Hugging Face",
    body: "Public Hugging Face repo (owner/model) — fetched via the HF resolve API",
  },
  {
    value: "local_path",
    label: "Local path",
    body: "Path to a model artifact on the scanner host (offline analysis)",
  },
];

const FORMAT_HINT_OPTIONS: MlFormatHint[] = [
  "auto",
  "pickle",
  "pytorch",
  "safetensors",
  "keras",
  "h5",
  "savedmodel",
  "gguf",
  "joblib",
];

export function MlModelFormSection({
  name,
  setName,
  sourceType,
  setSourceType,
  url,
  setUrl,
  hfRepo,
  setHfRepo,
  hfRevision,
  setHfRevision,
  localPath,
  setLocalPath,
  formatHint,
  setFormatHint,
  maxBytes,
  setMaxBytes,
}: {
  name: string;
  setName: (v: string) => void;
  sourceType: MlSourceType;
  setSourceType: (v: MlSourceType) => void;
  url: string;
  setUrl: (v: string) => void;
  hfRepo: string;
  setHfRepo: (v: string) => void;
  hfRevision: string;
  setHfRevision: (v: string) => void;
  localPath: string;
  setLocalPath: (v: string) => void;
  formatHint: MlFormatHint;
  setFormatHint: (v: MlFormatHint) => void;
  maxBytes: number;
  setMaxBytes: (v: number) => void;
}) {
  return (
    <div className="space-y-8">
      <section>
        <SectionIntro
          eyebrow="ML Model / Pipeline"
          title="Tell Pencheff where the model artifact is"
          description="Pencheff fetches and inspects the model file as data. It does not load or execute the model."
        />
        <div className="grid gap-5 md:grid-cols-2">
          <div>
            <Label>Name</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Production model"
            />
          </div>
          <div>
            <Label>Model location type</Label>
            <select
              value={sourceType}
              onChange={(e) => setSourceType(e.target.value as MlSourceType)}
              className="block w-full border border-hairline bg-paper px-3 py-2 text-[13px] text-graphite focus:outline-none focus:border-ink"
            >
              {SOURCE_TYPE_OPTIONS.map(({ value, label }) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
            <FieldHint>
              {SOURCE_TYPE_OPTIONS.find((option) => option.value === sourceType)
                ?.body}
            </FieldHint>
          </div>

        {sourceType === "file_url" && (
          <div className="md:col-span-2">
            <Label>Model artifact URL</Label>
            <Input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://host/model.safetensors"
              className="font-mono text-[13px]"
            />
            <FieldHint>Use a direct HTTPS URL to the model file.</FieldHint>
          </div>
        )}

        {sourceType === "huggingface" && (
          <>
            <div>
              <Label>Hugging Face repo</Label>
              <Input
                value={hfRepo}
                onChange={(e) => setHfRepo(e.target.value)}
                placeholder="owner/model"
                className="font-mono text-[13px]"
              />
              <FieldHint>Example format: organization/model-name.</FieldHint>
            </div>
            <div>
              <Label>Revision</Label>
              <Input
                value={hfRevision}
                onChange={(e) => setHfRevision(e.target.value)}
                placeholder="main"
                className="font-mono text-[13px]"
              />
              <FieldHint>Leave blank to use the repo default branch.</FieldHint>
            </div>
          </>
        )}

        {sourceType === "local_path" && (
          <div className="md:col-span-2">
            <Label>Local model path</Label>
            <Input
              value={localPath}
              onChange={(e) => setLocalPath(e.target.value)}
              placeholder="/models/model.pt"
              className="font-mono text-[13px]"
            />
            <FieldHint>Path on the scanner host, not your browser.</FieldHint>
          </div>
        )}
        </div>
      </section>

      <AdvancedSection
        title="Advanced model inspection settings"
        description="Auto-detect is best for most scans. Change these only when you already know the file type or need a smaller fetch cap."
      >
        <div className="grid gap-5">
          <div>
            <Label>Format hint</Label>
            <select
              value={formatHint}
              onChange={(e) => setFormatHint(e.target.value as MlFormatHint)}
              className="block w-full border border-hairline bg-paper p-3 font-mono text-[13px] text-graphite focus:outline-none focus:border-ink"
            >
              {FORMAT_HINT_OPTIONS.map((opt) => (
                <option key={opt} value={opt}>
                  {opt}
                </option>
              ))}
            </select>
          </div>
          <div>
            <Label>Max fetch size (bytes)</Label>
            <Input
              type="number"
              value={maxBytes}
              onChange={(e) => setMaxBytes(Number(e.target.value))}
              className="font-mono text-[13px]"
            />
            <FieldHint>Fetch size cap in bytes.</FieldHint>
          </div>
        </div>
      </AdvancedSection>
    </div>
  );
}

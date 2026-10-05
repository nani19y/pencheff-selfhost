import { graphJsonLd, type JsonLdObject } from "@/lib/structured-data";

function serializeJsonLd(data: JsonLdObject | JsonLdObject[]) {
  const payload = Array.isArray(data) ? graphJsonLd(data) : data;
  return JSON.stringify(payload).replace(/</g, "\\u003c");
}

export function JsonLd({
  data,
  id = "pencheff-json-ld",
}: {
  data: JsonLdObject | JsonLdObject[];
  id?: string;
}) {
  return (
    <script
      id={id}
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: serializeJsonLd(data) }}
    />
  );
}

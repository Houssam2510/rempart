"use client";
import DOMPurify from "dompurify";
import { useSearchParams } from "next/navigation";

export default function Search() {
  const params = useSearchParams();
  const q = params.get("q") ?? "";
  return (
    <div>
      {/* rempart-expect: CODE-XSS-SINK */}
      <h1 dangerouslySetInnerHTML={{ __html: q }} />
      {/* rempart-safe: CODE-XSS-SINK */}
      <p dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(q) }} />
    </div>
  );
}

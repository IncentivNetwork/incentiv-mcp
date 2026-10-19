/** Transport paths and queries may contain provider credentials. */
export function publicServiceUrl(value: string): string {
  return new URL(value).origin;
}

/** Preserve useful error details without publishing credential-bearing URLs. */
export function publicErrorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  // Quotes and backticks are legal path characters, not safe token terminators.
  return message.replace(/https?:\S+/gi, (value) => {
    try { return publicServiceUrl(value.replace(/\\\//g, "/")); }
    catch { return "[redacted URL]"; }
  });
}

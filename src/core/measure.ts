import crypto from "node:crypto";
import { PROTECTED_AST_SIGNATURE_ID } from "./limits.js";

export function sha256Buffer(buf: Buffer): string {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

/**
 * Independently detect the protected-process shim AST signature from bytes.
 * A hash or AST id merely declared in incident JSON never proves itself.
 *
 * Pattern: three assignment statements that redefine global process/globalThis.
 */
export function measureProtectedProcessAst(source: string): {
  matched: boolean;
  signatureId: string | null;
  assignmentCount: number;
} {
  // Normalize newlines; do not execute.
  const text = source.replace(/\r\n/g, "\n");
  const patterns = [
    /globalThis\s*\.\s*process\s*=/,
    /global\s*\.\s*process\s*=/,
    /(?:^|[^\w$.])process\s*=/,
  ];
  let assignmentCount = 0;
  for (const re of patterns) {
    if (re.test(text)) assignmentCount += 1;
  }
  // Require all three distinct redefinition forms.
  const matched = assignmentCount >= 3;
  return {
    matched,
    signatureId: matched ? PROTECTED_AST_SIGNATURE_ID : null,
    assignmentCount,
  };
}

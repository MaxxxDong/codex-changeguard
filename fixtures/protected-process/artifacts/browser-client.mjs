// ChangeGuard synthetic fixture — not production Codex bytes.
// Signature: js.global-process-shim-redefinition.v1
// Exact three-statement protected-process shim block (structural match).
const __cg_shim = Object.create(null);
globalThis.process = __cg_shim;
globalThis.global = globalThis.global ?? globalThis;
globalThis.global.process = __cg_shim;
export const marker = "protected-process-shim";

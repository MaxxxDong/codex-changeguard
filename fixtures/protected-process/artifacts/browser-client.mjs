// ChangeGuard synthetic fixture — not production Codex bytes.
// Signature: js.global-process-shim-redefinition.v1
// Three assignment statements that redefine global process binding.
const __cg_shim = Object.create(null);
globalThis.process = __cg_shim;
global.process = __cg_shim;
process = __cg_shim;
export const marker = "protected-process-shim";

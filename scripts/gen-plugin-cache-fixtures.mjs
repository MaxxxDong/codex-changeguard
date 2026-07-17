/** One-shot fixture generator for Ticket 08 plugin-cache scenarios. */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "fixtures",
  "plugin-cache",
);
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");

const TRUSTED = `// ChangeGuard trusted plugin entry v1.2.0
export const PLUGIN_ID = "codex-plugin-entry";
export const VERSION = "1.2.0";
export function health() {
  return { ok: true, version: VERSION };
}
`;

const CORRUPT = `// CORRUPTED plugin entry
export const PLUGIN_ID = "codex-plugin-entry";
export const VERSION = "1.2.0";
export function health() {
  return { ok: false, version: VERSION, corrupt: true };
}
`;

const STALE = `// Stale shared cache entry v1.0.0 gen2
export const PLUGIN_ID = "codex-plugin-entry";
export const VERSION = "1.0.0";
export function health() {
  return { ok: true, version: VERSION, generation: 2 };
}
`;

const SKEW = `// Version-skewed entry
export const PLUGIN_ID = "codex-plugin-entry";
export const VERSION = "0.9.0";
export function health() {
  return { ok: true, version: VERSION };
}
`;

const LOCAL_INTENT = `// Local override that reconciliation should not silently discard
export const PLUGIN_ID = "codex-plugin-entry";
export const VERSION = "1.2.0";
export const LOCAL_PATCH = true;
export function health() {
  return { ok: true, version: VERSION, local: true };
}
`;

const BUNDLED_GOOD = TRUSTED;
const trustedSha = sha(TRUSTED);
const corruptSha = sha(CORRUPT);
const staleSha = sha(STALE);
const skewSha = sha(SKEW);
const localSha = sha(LOCAL_INTENT);
const bundledSha = sha(BUNDLED_GOOD);

function write(p, content) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
}

function identityHash(alias, generation) {
  return sha(`cache-identity-v1:${alias}:${generation}`);
}

function incident(mechanismMsg) {
  return {
    schema_version: 1,
    codex_version: "0.1.0-fixture",
    build_sha: null,
    surface: "plugin",
    platform: { os: "macos", arch: "arm64", sandbox_class: "plugin_runtime" },
    failure_phase: "hook_load",
    error: {
      class: "PluginLoadError",
      normalized_message: mechanismMsg,
      message_digest: sha(mechanismMsg),
    },
    stack_frames: [
      {
        module: "plugin-loader",
        file: "entry.js",
        symbol: "load_plugin",
        line_bucket: 10,
      },
    ],
    config_keys: [],
    feature_ids: ["bundled_plugin"],
    artifact_hashes: [],
    ast_signature_ids: [],
    local_facts_digest: sha("pending"),
  };
}

function baseManifest(expectedSha, rebuildSha = trustedSha) {
  return {
    schema_version: 1,
    required_generation: 5,
    required_version: "1.2.0",
    components: [
      {
        alias: "PLUGIN_CACHE_ENTRY",
        expected_sha256: expectedSha,
        version: "1.2.0",
        provenance: "bundled",
      },
    ],
    rebuild_source: {
      alias: "TRUSTED_PLUGIN_ENTRY",
      verified: true,
      expected_sha256: rebuildSha,
      version: "1.2.0",
    },
  };
}

function inventory({
  generation,
  version,
  provenance,
  declared,
  depFail = false,
  instance = "inst_plugin_cache_a",
}) {
  return {
    schema_version: 1,
    instance_id: instance,
    cache_identity: {
      alias: "SHARED_PLUGIN_CACHE_A",
      identity_hash: identityHash("SHARED_PLUGIN_CACHE_A", generation),
      generation,
    },
    components: [
      {
        alias: "PLUGIN_CACHE_ENTRY",
        version,
        provenance,
        declared_sha256: declared,
      },
    ],
    dependency_install_failure: depFail,
  };
}

function health() {
  return { schema_version: 1, ok: true };
}

function writeCommon(dir, { trusted, bundled, cache, inv, man, recon, localIntent, msg }) {
  write(path.join(dir, "plugin-cache/trusted/entry.js"), trusted);
  write(path.join(dir, "plugin-cache/bundled/entry.js"), bundled);
  write(path.join(dir, "plugin-cache/cache/entry.js"), cache);
  write(path.join(dir, "plugin-cache/inventory.json"), `${JSON.stringify(inv, null, 2)}\n`);
  write(path.join(dir, "plugin-cache/manifest.json"), `${JSON.stringify(man, null, 2)}\n`);
  write(path.join(dir, "plugin-cache/health.json"), `${JSON.stringify(health(), null, 2)}\n`);
  if (recon) {
    write(
      path.join(dir, "plugin-cache/recon-state.json"),
      `${JSON.stringify(recon, null, 2)}\n`,
    );
  }
  if (localIntent) {
    write(path.join(dir, "plugin-cache/local-intent.js"), localIntent);
  }
  write(path.join(dir, "incident.json"), `${JSON.stringify(incident(msg), null, 2)}\n`);
}

// corruption
writeCommon(path.join(root, "corruption"), {
  trusted: TRUSTED,
  bundled: BUNDLED_GOOD,
  cache: CORRUPT,
  inv: inventory({
    generation: 5,
    version: "1.2.0",
    provenance: "bundled",
    declared: corruptSha,
  }),
  man: baseManifest(trustedSha),
  msg: "bundled plugin entry failed integrity check",
});

// stale-cache
writeCommon(path.join(root, "stale-cache"), {
  trusted: TRUSTED,
  bundled: BUNDLED_GOOD,
  cache: STALE,
  inv: inventory({
    generation: 2,
    version: "1.2.0",
    provenance: "shared_cache",
    declared: staleSha,
  }),
  man: baseManifest(trustedSha),
  msg: "shared plugin cache appears stale after update",
});

// version-skew
writeCommon(path.join(root, "version-skew"), {
  trusted: TRUSTED,
  bundled: BUNDLED_GOOD,
  cache: SKEW,
  inv: inventory({
    generation: 5,
    version: "0.9.0",
    provenance: "shared_cache",
    declared: skewSha,
  }),
  man: baseManifest(trustedSha),
  msg: "plugin dependency version mismatch after upgrade",
});

// reconciliation (repairable)
writeCommon(path.join(root, "reconciliation"), {
  trusted: LOCAL_INTENT,
  bundled: BUNDLED_GOOD,
  cache: BUNDLED_GOOD,
  inv: inventory({
    generation: 5,
    version: "1.2.0",
    provenance: "bundled",
    declared: bundledSha,
  }),
  man: baseManifest(localSha, localSha),
  recon: {
    schema_version: 1,
    last_cycle_overwrote_local: true,
    will_overwrite_on_next_cycle: false,
    local_intent_sha256: localSha,
  },
  localIntent: LOCAL_INTENT,
  msg: "plugin local change rewritten by reconciliation",
});

// reconciliation-recurs
writeCommon(path.join(root, "reconciliation-recurs"), {
  trusted: LOCAL_INTENT,
  bundled: BUNDLED_GOOD,
  cache: BUNDLED_GOOD,
  inv: inventory({
    generation: 5,
    version: "1.2.0",
    provenance: "bundled",
    declared: bundledSha,
    instance: "inst_plugin_cache_recur",
  }),
  man: baseManifest(localSha, localSha),
  recon: {
    schema_version: 1,
    last_cycle_overwrote_local: true,
    will_overwrite_on_next_cycle: true,
    local_intent_sha256: localSha,
  },
  localIntent: LOCAL_INTENT,
  msg: "plugin change reappears after reconciliation",
});

// negative-control
writeCommon(path.join(root, "negative-control"), {
  trusted: TRUSTED,
  bundled: BUNDLED_GOOD,
  cache: CORRUPT,
  inv: inventory({
    generation: 5,
    version: "1.2.0",
    provenance: "shared_cache",
    declared: corruptSha,
    depFail: true,
    instance: "inst_plugin_cache_neg",
  }),
  man: baseManifest(trustedSha),
  msg: "plugin failed to load after update",
});

console.log(
  JSON.stringify(
    {
      trustedSha,
      corruptSha,
      staleSha,
      skewSha,
      localSha,
      bundledSha,
    },
    null,
    2,
  ),
);
console.log("fixtures written under", root);

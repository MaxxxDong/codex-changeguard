import type {
  CaseKind,
  FormBlobRecord,
  GitHubIssueForm,
  ProductSurfaceHint,
  UpstreamRoute,
} from "./types.js";
import { filenameForFormRole } from "./form-snapshot.js";

export interface RouteDecision {
  route: UpstreamRoute;
  github_issue_form: GitHubIssueForm | null;
  form_filename: string | null;
  rationale: string;
  /** Security must never render a public Issue draft. */
  public_issue_draft_forbidden: boolean;
}

/**
 * Deterministic channel routing:
 * - validated security → Bugcrowd (private; never public Issue)
 * - account/billing/private → OpenAI Support
 * - product support questions → GitHub Discussions
 * - Codex product bugs → GitHub Issue (+ form map)
 */
export function routeUpstream(case_kind: CaseKind): RouteDecision {
  switch (case_kind) {
    case "validated_security_vulnerability":
      return {
        route: "BUGCROWD",
        github_issue_form: null,
        form_filename: null,
        rationale:
          "Validated security vulnerabilities route privately to OpenAI Bugcrowd and never render a public Issue draft.",
        public_issue_draft_forbidden: true,
      };
    case "account_billing_private":
      return {
        route: "OPENAI_SUPPORT",
        github_issue_form: null,
        form_filename: null,
        rationale:
          "Account, billing, and private cases route to OpenAI Support (out of public Issue scope).",
        public_issue_draft_forbidden: true,
      };
    case "product_support_question":
      return {
        route: "GITHUB_DISCUSSIONS",
        github_issue_form: null,
        form_filename: null,
        rationale:
          "Product support questions route to GitHub Discussions rather than a bug Issue form.",
        public_issue_draft_forbidden: false,
      };
    case "codex_product_bug":
      return {
        route: "GITHUB_ISSUE",
        github_issue_form: null, // filled by form map
        form_filename: null,
        rationale:
          "Codex product bugs route to an openai/codex GitHub Issue using the current surface form.",
        public_issue_draft_forbidden: false,
      };
    default: {
      const _exhaustive: never = case_kind;
      void _exhaustive;
      return {
        route: "GITHUB_ISSUE",
        github_issue_form: null,
        form_filename: null,
        rationale: "Unknown case kind fell closed to product-bug Issue path.",
        public_issue_draft_forbidden: false,
      };
    }
  }
}

/** Default filenames matching the bundled 2026-07-18 official snapshot facts. */
const DEFAULT_FORM_FILENAMES: Record<GitHubIssueForm, string> = {
  APP: "1-codex-app.yml",
  CLI: "3-cli.yml",
  EXTENSION: "2-extension.yml",
  OTHER: "4-bug-report.yml",
};

/**
 * Map product surface to current official Issue form role.
 * Filename prefers the validated current snapshot role when provided;
 * falls back to bundled snapshot defaults (not ad-hoc hardcodes elsewhere).
 */
export function mapGitHubIssueForm(
  surface: ProductSurfaceHint,
  forms?: readonly FormBlobRecord[] | null,
): {
  form: GitHubIssueForm;
  filename: string;
} {
  let form: GitHubIssueForm;
  switch (surface) {
    case "app":
    case "desktop":
      form = "APP";
      break;
    case "cli":
      form = "CLI";
      break;
    case "extension":
    case "ide":
    case "browser_control":
      form = "EXTENSION";
      break;
    case "other":
    case "unknown":
    default:
      form = "OTHER";
      break;
  }
  const fromSnapshot =
    forms && forms.length > 0 ? filenameForFormRole([...forms], form) : null;
  return {
    form,
    filename: fromSnapshot ?? DEFAULT_FORM_FILENAMES[form],
  };
}

export function applyFormMap(
  decision: RouteDecision,
  surface: ProductSurfaceHint,
  forms?: readonly FormBlobRecord[] | null,
): RouteDecision {
  if (decision.route !== "GITHUB_ISSUE") return decision;
  const mapped = mapGitHubIssueForm(surface, forms);
  return {
    ...decision,
    github_issue_form: mapped.form,
    form_filename: mapped.filename,
  };
}

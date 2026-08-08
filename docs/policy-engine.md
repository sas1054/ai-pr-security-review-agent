# Natural-language policy-to-control engine

The control portal accepts policy text in business language and turns it into proposed, testable controls. Administrators do not author regular expressions or Semgrep rules in this workflow. Legacy rule packs remain available only for compatibility.

## Workflow

1. Open **Policies** and paste text, upload a PDF/DOCX/TXT document, or provide a public HTTPS URL.
2. The gateway stores an immutable source version and queues a `policy_ingestion` job.
3. The worker extracts text and source locations, asks Azure OpenAI for structured obligations, validates every quoted excerpt against the source, compiles typed detector artifacts, and executes generated positive and negative tests.
4. Review the plain-language controls in **Controls**. Ambiguous controls stay in `needs_clarification` until every question is answered.
5. A user with `Policy.Approver` approves each validated control. A user with `Policy.Activator` activates it.
6. Future Azure DevOps PR reviews execute active controls. Findings cite the exact policy version and source clause.

Control states are `draft`, `needs_clarification`, `approved`, `active`, `suspended`, and `retired`. Approved or active content is never edited in place; **New version** creates another draft. Activating it retires the previous active control version while preserving its source and detector artifact.

## Supported execution strategies

- Literal/value matching for source and configuration values.
- Structured JSON/YAML and assignment-based Terraform, Bicep, Docker, and deployment configuration inspection.
- Pattern controls with bounded, prevalidated expressions.
- AST/import/call controls through validated Semgrep artifacts.
- Exact and subdomain-aware URL/domain controls.
- Direct and lock-file dependency controls for npm, Python, NuGet, Maven/Gradle, and Go.
- Semantic and manual-review controls that can create non-blocking human-review findings but can never declare compliance or suppress deterministic results.

Changed files are always scanned. When dependency or configuration controls require it, the worker also fetches a bounded set of relevant manifests, lock files, and deployment files from the PR source branch. Any unsupported or truncated coverage is recorded in the review evidence.

## API contracts

All paths are below `/api/admin/api`:

- `GET|POST /policies` lists policies or creates paste/upload/URL ingestion. Add `id` and `version` query parameters to retrieve extracted clauses, analysis, and generated controls.
- `GET /policy-job?id=<job-id>` returns asynchronous ingestion state.
- `GET /controls` lists every immutable control version.
- `POST /control-action` performs `clarify`, `revise`, `approve`, `activate`, `suspend`, or `retire`.
- `GET|POST /exceptions` lists or approves scoped exceptions.
- `POST /exception-action` revokes an exception.
- `GET /audit` returns actor-stamped policy, control, exception, and review lifecycle events.

Uploads use JSON with `content_base64`, `filename`, and `media_type`. The portal handles this encoding automatically. Source and generated artifacts are stored in the `policy-artifacts` blob container; Table Storage records hold bounded metadata and artifact hashes.

## URL and document safety

- Maximum source size is 20 MB.
- URL ingestion accepts unauthenticated HTTPS on port 443 only.
- Private, loopback, link-local, multicast, and reserved targets are rejected after DNS resolution.
- Redirects are revalidated and limited to three.
- Accepted URL media types are PDF, DOCX, and plain text.
- Image-only PDFs fail with `needs_clarification`; the service does not invent text or silently perform OCR.

## Exceptions and audit evidence

An exception records the control/version, project or repository, approved matched value, business justification, approver, approval time, expiration, and reference ticket. Expired and revoked exceptions stop suppressing findings automatically. Suppressed deterministic findings remain in the immutable review record with the matching exception snapshot.

Every review stores active control and policy versions, detector hashes, applicable exception snapshots, visible and suppressed findings, source citations, and coverage gaps. This is sufficient to locate the immutable artifacts used by a historic review.

## Production identity

Set the production Bicep parameters `enableAdminEntraAuth=true`, `adminEntraClientId`, and `adminEntraTenantId`. Configure these app roles on the Entra application:

- `Policy.Author`
- `Policy.Approver`
- `Policy.Activator`
- `Exception.Approver`
- `Policy.Admin` (all permissions)

The webhook and health paths remain excluded from Easy Auth because Azure DevOps uses the existing webhook key. Local and temporary hackathon deployments may keep key-only administration; never use that mode for production policy approval.

## Operational checks

- Watch ingestion jobs for `failed` and inspect their bounded error list.
- Treat citation-validation failures as rejected proposals, not model output to approve manually.
- Do not activate controls whose generated test result is not `passed`.
- Review `coverage_gaps` in every historic review before making an audit assertion.
- Keep PR enforcement advisory-only until pilot false-positive and coverage metrics are accepted.

# Policy and reference knowledge

> **Portal UX:** Reference-only sources now live in the **Policies** page beside enforceable policy sources. They are
> labeled *Reference only* and can be approved or retired there; the underlying `regulation` storage/API names remain
> for backward compatibility with existing citations and review evidence.

> **Current capability:** The natural-language policy engine described in [policy-engine.md](policy-engine.md) now sits above this original rule-pack/regulation layer. Rule packs remain backward compatible, while new policies use immutable documents, citation-verified proposals, typed controls, per-control approval, exceptions, and review snapshots. Keyword regulation retrieval remains contextual evidence and does not replace executable controls.

## What is live in the first build

The admin portal stores two kinds of customer-controlled security knowledge in
the existing Storage account. No new search service is deployed for this
phase.

- **Rule packs** are versioned collections of simple regex rules and/or
  Semgrep YAML rules. A pack is `draft`, `active`, or `retired`. Activating a
  newer version retires the previous active version of the same pack.
- **Regulations** are versioned source documents with an owner, effective date,
  source URL, tags, and approval state. The source is held in Blob Storage and
  chunks plus metadata are held in Table Storage.
- During a review, only active rule packs scan the PR. Only approved regulation
  chunks can be retrieved. The review record captures the policy versions and
  regulation citations that were considered.

This first retrieval mode is a deterministic keyword match. It is deliberately
small, cheap, and auditable: it is suitable for a hackathon pilot and does not
create embedding or search charges while the service is idle.

## Safety rules

1. The scanner's Semgrep and secret findings remain deterministic facts. A
   policy pack or model may add context, but neither can delete those findings.
2. A regulation must be marked `approved` before it can influence a review.
   `draft` content is searchable only by the portal list, not by the worker.
3. Replacing a regulation creates a new version. Retire the older version only
   after the new one is approved.
4. Do not put production secrets, unredacted incident evidence, or personal
   data in regulation text. The worker can send retrieved excerpts to the
   configured Azure OpenAI deployment as review context.

## Future vector RAG activation

When keyword matching is no longer sufficient, add Azure AI Search without
changing the portal, scanner, triage payload, or persisted review contract.

```text
Blob source document ──> chunking + embeddings ──> Azure AI Search index
                                                       │
PR findings + changed-code summary ──> hybrid search ──┘
                                      │
                                      └──> existing regulation-context payload
                                                └──> Azure OpenAI triage
```

The vector adapter should preserve the current result fields:
`document_id`, `title`, `version`, `effective_date`, `source_url`, `chunk_id`,
`content`, and `score`. Add `retrieval_method` and `citation_id` rather than
altering existing fields. Use metadata filters for `status=approved` and an
effective-date check before result ranking.

Recommended activation sequence:

1. Provision Azure AI Search only after the pilot demonstrates a retrieval
   quality need; keep the low-cost profile on keyword retrieval beforehand.
2. Use managed identity for Search and Azure OpenAI. Store no search key in the
   portal.
3. Backfill embeddings from approved regulation versions, recording model and
   chunking settings in each index document.
4. Run keyword and hybrid retrieval in parallel for selected reviews, compare
   citations, then switch the `rag_mode` setting to `hybrid`.
5. Keep a fallback to keyword retrieval when Search is unavailable. A retrieval
   outage must never turn a deterministic scanner finding into a clean result.

Azure AI Search has a free tier with service limits, but it is a persistent
service rather than scale-to-zero. It is intentionally not part of the
first-phase deployment budget.

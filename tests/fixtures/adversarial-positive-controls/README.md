# Adversarial positive-control rationale

Every credential-shaped value is synthetic. The fixture contains no real
credential, endpoint, project reference, username, email address, absolute
home path, or third-party source.

| Repository file | Expected signal | Rule stressed | Why a finding is correct |
|---|---|---|---|
| `.env.local` | A high-entropy literal in a real local environment file | `generic-high-entropy-assignment` | Real `.env.local` files are force-scanned and must not inherit `.env.example` suppression. |
| `docs/my-node_modules-notes.md` | A high-entropy literal in a longer path segment | `generic-high-entropy-assignment` | `node_modules` allowlisting uses whole segments, not substrings. |
| `tests/stripe.test.ts` | A synthetic `sk_test_` credential in a test | `stripe-secret-key` | Stripe test credentials still authorize test-mode operations; until per-rule severity exists, detection is safer than silence. |
| `src/aws-production-shape.ts` | An AWS-shaped identifier without a placeholder marker | `aws-access-key-id` | Case-insensitive placeholder suppression must not swallow an otherwise genuine-shaped credential. |
| `src/aws-preceding-comment.ts` | A placeholder word occurs only on the preceding line | `aws-access-key-id` | Line-context suppression is outside Track L; a separate comment must not hide the next line's credential. |

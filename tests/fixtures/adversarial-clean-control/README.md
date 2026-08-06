# Adversarial clean-control rationale

Every value in this fixture is synthetic. The fixture contains no real
credential, endpoint, project reference, username, email address, absolute
home path, or third-party source.

| Repository file | Naive signal | Rule stressed | Why zero findings is correct |
|---|---|---|---|
| `assets/content-hash.ts` | A high-entropy hexadecimal value assigned to `assetToken` | `generic-high-entropy-assignment` | The value is immutable build metadata, not authentication material. |
| `fixtures/payload.ts` | Base64 assigned to `testCredential` | `generic-high-entropy-assignment` | The value is an inert fixture payload identified by its test-only binding. |
| `build/metadata.ts` | A 40-character hexadecimal value assigned to `buildToken` | `generic-high-entropy-assignment` | The value is a synthetic Git object identifier. |
| `sessions/example.ts` | A UUIDv4 assigned to `sessionToken` | `generic-high-entropy-assignment` | The value is a public correlation identifier, not a bearer credential. |
| `password-low-entropy.ts` | A long literal assigned to `password` | `generic-high-entropy-assignment` | Repetition keeps the value below the rule's entropy threshold. |
| `env-reference.ts` | `apiKey` points at an environment variable | `generic-high-entropy-assignment` | No literal secret is present. |
| `empty-secret.ts` | An assignment uses the `secret` keyword | `generic-high-entropy-assignment` | The assigned value is empty. |
| `dist/minified.js` | A high-entropy token assignment appears on a minified line | `generic-high-entropy-assignment` | The rule intentionally suppresses generic matches above its minified-line threshold. |
| `docs/aws-example.md` | The canonical AWS documentation access-key ID | `aws-access-key-id` | The `EXAMPLE` marker makes this a documented placeholder. |
| `README.md` | A three-segment JWT | `supabase-legacy-jwt` | The token has an empty claims object and exists only to document JWT structure. |
| `SECURITY.md` | A private-key header | `private-key-block` | A backtick-quoted header names the prohibited material but contains no key block. |
| `stories/Auth.stories.ts` | An OpenAI-shaped `sk-proj-` string | `openai-api-key` | The value is a synthetic Storybook story identifier. |
| `.env.example` | A secret-shaped literal in an environment template | global path allowlist | Example environment files are templates and are allowlisted by architecture §5. |
| `deno.lock` | Integrity-like high-entropy material | generic/provider rules | Integrity metadata is public dependency verification material. |
| `bun.lock` | Integrity-like high-entropy material | generic/provider rules | Integrity metadata is public dependency verification material. |
| `public/server/config.json` | A client root contains a `server` segment | location classifier | The content is inert; the path pins the L2 precedence hypothesis. |
| `app/server/page.tsx` | An app route contains a `server` segment | location classifier | The content is inert; the path pins the L2 precedence hypothesis. |
| `services/worker/dist/index.js` | A server worker has a `dist` segment | location classifier | The content is inert; the path pins the L2 inflation hypothesis. |
| `app/api/(admin)/route.ts` | A route group sits below `app/api` | location classifier | Next.js route handlers remain server-only through route-group nesting. |
| `src/app/@modal/(.)photo/page.tsx` | Parallel and intercepting route segments | location classifier | The path remains browser-reachable under the `src/app` root. |
| `search/public-client.ts` | A high-entropy `apiKey` is intentionally browser-visible | `generic-high-entropy-assignment` | The binding explicitly identifies a public search client credential; a generic secret finding is noise. |
| `docs/commented-bearer.ts` | A Supabase-shaped bearer token appears in a commented command | `supabase-legacy-jwt` | The explicit same-line `vibescan:allow` marker documents an intentional non-executable example without broad comment suppression. |
| `package.json` | A package manifest is present | dependency integrity | The empty dependency sets are structurally valid. |

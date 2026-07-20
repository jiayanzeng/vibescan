# vibescan Licensing FAQ

This page explains vibescan's license in plain language so you can tell quickly
whether your use is free or needs a paid commercial license.

> **This FAQ is guidance, not the license.** The binding document is
> [LICENSE](LICENSE) — the PolyForm Noncommercial License 1.0.0. If anything here
> ever seems to conflict with LICENSE, **LICENSE wins**. This page does not grant
> or remove any rights; it only describes the license in everyday terms. It is not
> legal advice.

## The short version

vibescan's command-line tool is **free for noncommercial use** and **free for
nonprofit, educational, research, and government use**. If you are using it to make
money — inside a for-profit business, or as paid work auditing someone else's
commercial codebase — you need a **commercial license**.

## Is my use free, or do I need a commercial license?

| You are… | Using vibescan for… | Cost |
|---|---|---|
| A student, hobbyist, or independent tinkerer | Personal projects, learning, side projects that don't earn money | **Free** |
| A researcher (including at a university or public research institute) | Study or research | **Free** |
| A nonprofit / charity / school / public-health / government worker | Your organization's own work | **Free** |
| Anyone | *Evaluating* whether to buy a commercial license | **Free** |
| An employee, contractor, or founder of a **for-profit** company | Company work — scanning your employer's or client's code as part of your job | **Commercial license** |
| A consultant / agency / auditor | **Paid** security work for a commercial client | **Commercial license** |

The line is **the purpose of the work, and who benefits from it** — not simply
whether you happen to have a job. Working at a company doesn't automatically make
your use commercial (see the nonprofit/university row above); doing **for-profit
work** with the tool does.

## Concrete examples

**Free (noncommercial):**

- You run vibescan on your own weekend Supabase app that has no revenue.
- You're a CS student scanning a class project.
- You're a security researcher testing vibescan against sample repos for a paper.
- You work at a registered nonprofit and scan the nonprofit's own application.
- You work at a university or a government agency and scan that institution's code.
- Your company is deciding whether to adopt vibescan and someone runs a trial to
  evaluate it.

**Needs a commercial license (for-profit):**

- You're an engineer at a for-profit startup and you run vibescan on the company's
  codebase as part of your job.
- You run a security consultancy and you scan a paying client's repository.
- You bundle vibescan into a paid product or a paid service you sell.
- You use vibescan inside a for-profit company's CI pipeline.

## Why the "nonprofit / university / government is free" carve-out?

Because that's what the PolyForm Noncommercial License actually says. The license
explicitly treats use by charitable organizations, educational institutions, public
research organizations, public-safety and health organizations, environmental
organizations, and government institutions as **permitted (free) — regardless of how
that organization is funded.** We don't want to tell those users they owe money when
the license already gives it to them for free.

## Gray areas — when in doubt, ask

Some situations aren't clear-cut (a nonprofit with a commercial subsidiary; an
open-source maintainer who also does paid consulting; a solo developer about to turn
a hobby app into a business). If you're not sure, **ask before you rely on it** — open
an issue or contact the maintainer via the project's GitHub page:
<https://github.com/jiayanzeng/vibescan>. We'd rather answer a question than have a
misunderstanding. Asking in good faith is always fine.

## How do I get a commercial license?

Open an issue or reach the maintainer through
<https://github.com/jiayanzeng/vibescan>. Commercial licenses cover for-profit use
of the CLI; a separate paid **desktop application** is planned as its own
commercially-licensed product.

## Why isn't this "open source"?

Because "open source," as the term is formally defined, is not allowed to restrict
commercial use — and this license does. The accurate label is **source-available**:
the source is public so anyone can read, audit, and learn from it and use it for
noncommercial purposes, but commercial use is reserved. Calling it "open source"
would misstate the terms, so we don't.

## It's on crates.io and npm — is that allowed? Can I install it from there?

Yes. Both crates.io and npm accept non-open-source license identifiers, and we
publish the free CLI there so it's easy to install with `cargo install` or `npx`.
**Installing it from a public registry does not change the license** — whatever you
install is still under the PolyForm Noncommercial terms above. Install it, use it for
any permitted (noncommercial or nonprofit/edu/gov/research) purpose for free; use it
for for-profit work and you need a commercial license, exactly as on this page. The
paid desktop app will **not** be distributed through these public registries.

## What about older versions (0.1.0–0.1.3)?

Versions **0.1.0 through 0.1.3** were published under the **MIT License**, and an MIT
grant can't be taken back — so those specific versions stay usable under MIT for
anyone who already has them, including commercially. The PolyForm Noncommercial terms
apply to versions released **after 0.1.3**.

## What counts as "commercial use"? (Detailed definition)

Commercial use is about who benefits and in what context — not whether you resell the
software. You do not have to sell, sublicense, host, or make money from vibescan itself for
your use to be commercial. Use is commercial if it is in furtherance of, or provides a
commercial advantage to, a for-profit business or other commercial activity.

Commercial use includes, without limitation:
- Running vibescan on a for-profit company's own code or infrastructure — including
  internal security audits, secret-exposure scans, and CI/CD checks — to support that
  company's business or operations.
- Any use by an employee, contractor, or agent of a for-profit entity in the course of
  their work for that entity.
- Using vibescan to perform paid work (security audits, consulting, managed services) for
  a third party.
- Building vibescan into a product or service you provide to others, whether or not for a
  fee.

Personal, hobby, study, and research use with no anticipated commercial application, and
use by charitable, educational, public-research, public-safety/health, environmental, and
government organizations, remain free under the noncommercial license.

"We only use it internally and don't monetize the software" is not a noncommercial use:
internal use by a for-profit company to protect or improve its commercial systems is a
commercial application and requires a commercial license.

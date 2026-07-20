# Contributing to vibescan

Thanks for your interest in contributing. Please read this before opening a pull
request — contributions require a signed Contributor License Agreement (CLA).

## Why a CLA?

vibescan is offered under two kinds of terms: the free
[PolyForm Noncommercial License](LICENSE) for everyone, and separate **commercial
licenses** for for-profit use. For that dual-licensing model to work, the project
maintainer must be able to license **every** line of code in the project under both
sets of terms.

If an outside contribution came in with no agreement, that contributor would keep
copyright in their patch under the default noncommercial terms — and the maintainer
would **not** have the right to include it in a commercial license. A single such
patch could make the whole project impossible to license commercially. The CLA solves
this: you keep the copyright in your contribution, and you grant the maintainer a
broad license (including the right to license it commercially) so your work can ship
in every edition of vibescan.

### Why a CLA and not just a DCO?

The lightweight [Developer Certificate of Origin](https://developercertificate.org/)
(a `Signed-off-by` line) only certifies that you had the right to submit the code. It
does **not** grant the maintainer the right to relicense or dual-license it, so it is
not sufficient for a project that sells commercial licenses. vibescan therefore uses a
CLA with an explicit license grant.

## How to sign

**If you are contributing on your own behalf**, sign the
[Individual CLA](vibescan-cla-individual.md).

**If you are contributing as part of your job, or your employer has any rights in your
work**, your employer should sign the [Entity CLA](vibescan-cla-entity.md), in addition
to your individual sign-off. When in doubt, assume your employer needs to sign — many
employment agreements assign work product to the employer.

You can sign in whichever way the project has enabled:

- **Automated (recommended):** if the CLA Assistant bot is enabled, it will comment on
  your first pull request with a one-click link to sign. Your PR is gated until you do.
- **Manual:** copy the relevant CLA file, fill in your details and date at the bottom,
  and submit it as instructed in the pull request (for example, by adding your name to
  a `contributors` file or attaching the signed statement). The maintainer will
  confirm.

You only need to sign once; the agreement covers your future contributions too.

## What the CLA does and doesn't do

- You **keep** the copyright in your contribution. The CLA is a license grant, not an
  assignment — you can still use your own code however you like.
- You grant the maintainer a broad, irrevocable license to use your contribution and
  to license it to others under any terms, **including commercial licenses**.
- You confirm the contribution is your own work (or that you have the right to submit
  it) and mark any third-party material you include.

The exact terms are in the CLA documents; those control.

## Before you open a PR

- Discuss significant changes in an issue first, especially anything touching the
  architecture contract in `vibescan-architecture.md` — that document is authoritative,
  and changes to it are treated as spec changes.
- Keep the safety invariants intact: no new network egress outside the sanctioned
  feature-gated transports, and no changes that would weaken secret redaction or the
  own-assets-only boundary.
- Run `cargo test --workspace` and the boundary check
  (`bash scripts/check-network-boundary.sh`) before submitting.

> These CLA documents are drafts provided for legal review. They are not legal advice.

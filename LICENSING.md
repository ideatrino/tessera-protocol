# Licensing & Commercial Use

Copyright (c) 2026 Ideatrino <ideatrino@proton.me>. All Rights Reserved.

TESSERA uses a **dual-licensing** model so the project can stay open to view and
study while remaining commercially monetizable by the author.

> **Not legal advice.** This document explains intent. Before you rely on any of
> these terms commercially, have a qualified IP/technology lawyer review and, if
> needed, replace the `LICENSE` file with a vetted, jurisdiction-appropriate one.

## The two tracks

| Track | Who it's for | Terms |
|---|---|---|
| **Track 1 — Source-available / Non-commercial** | Researchers, students, hobbyists, evaluators | The included `LICENSE` (Proprietary, All Rights Reserved) grants free, royalty-free use for **non-commercial** evaluation, research, and study. |
| **Track 2 — Commercial license** | Companies / products that monetize, ship, or host the software | A separate paid agreement from the author. Removes the non-commercial restriction and can be tailored (per-seat, per-deployment, OEM, support/SLA). Contact **ideatrino@proton.me**. |

The default `LICENSE` in this repository is **Track 1**. Anything commercial
requires **Track 2**.

## Alternative models you can switch to

If you'd rather use a standard, court-tested license instead of a custom
proprietary one, three common monetization-friendly options are:

1. **AGPL-3.0 + Commercial (classic open-core dual license).**
   Release publicly under the GNU Affero GPL v3 (any networked use must release
   source). Companies that don't want that obligation buy a commercial license.
   Used by many successful open-core companies.

2. **Business Source License 1.1 (BUSL-1.1).**
   Source-available; free for non-production / limited use; commercial/production
   use needs a key; automatically converts to an open license (e.g. Apache-2.0)
   after a "Change Date" (commonly 4 years). Designed exactly for "public source
   + paid commercial."

3. **Fully proprietary / closed.**
   Keep the repository private and sell binaries or hosted access only.

You can adopt any of these by replacing `LICENSE` and updating the SPDX
identifier in `pyproject.toml`.

## A candid note on selling cryptography

The honest path to commercial value for a new cryptosystem runs through
**independent security audit and peer review** (see `SECURITY.md`). Marketing
unreviewed crypto as "secure" or "unbreakable" can create real legal and
reputational liability. The defensible value proposition is: *a clean, original,
transparent design — on a path to being audited* — not *"trust me, it's
unbreakable."*

Commercial licensing: **ideatrino@proton.me**

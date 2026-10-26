---
name: nist-nvd-guide
description: Resolve product identities and assess vulnerability evidence with nvd_* tools. Use for product/version applicability, interpreting CVSS and KEV context, complete vulnerability surveillance, or investigating CVE revisions.
license: Apache-2.0
metadata:
  author: cyanheads
  version: "1.0"
---

## Scope

Use NVD to investigate known CVEs, affected-product criteria, scoring, KEV catalog membership, and record changes. It does not discover installed software or prove an installation is secure. Description search discovers candidate CVEs; it does not establish product/version applicability or search advisory text and reference titles.

## Identifiers

- **CPEv2.3 name:** obtain it from `nvd_search_cpes`, inspect the product title and version, and retain the returned spelling and escaping. A vendor keyword can match several unrelated products. Inspect deprecation and replacement names before selecting an entry; do not silently substitute a different product or version.
- **CVE ID:** take it from a supplied advisory or the CVE records returned by search or audit. Reuse it for details, history, or the `nvd://cve/{cveId}` resource.
- **CWE ID:** take it from a known weakness classification or a full CVE record. The server has no CWE dictionary lookup. NVD placeholder classifications such as `NVD-CWE-Other` are not specific weaknesses.
- **Configuration group index:** groups nodes within one CVE record; it is not a CPE identifier or an ID accepted by another tool.

## Gates

1. **Before an applicability conclusion, establish the product identity.** Resolve ambiguous vendor/product matches rather than choosing the first search hit. If the installed product or version is unknown, keep the conclusion conditional on that missing fact.
2. **Before declaring a version affected, inspect its full configuration evidence.** Include configurations in the detail or audit response. Check inclusive/exclusive version bounds, each node's criteria, and the operator combining nodes in the same group. Preserve AND prerequisites and OR alternatives. A criterion marked non-vulnerable describes required context, not another independently vulnerable component.
3. **Before a negative conclusion, establish coverage.** Inspect totals, offsets, dropped-by-filter counts, notices, and analysis status. An empty filtered page, an offset beyond the result set, and no matching NVD records mean different things. A zero-total audit does not independently verify that the CPE exists. State “no known CVEs in NVD for this target and query” rather than “safe.”
4. **Before treating missing metadata as evidence, check analysis completeness.** A received or awaiting-analysis CVE can lack scores, weakness classifications, and affected-product criteria. If you excluded configurations or references from a response, fetch the required section before drawing a conclusion from its absence.
5. **Before comparing severity, identify the scoring basis.** The headline severity reflects the highest raw base score across available CVSS versions, not necessarily the severity matched by a search filter. Compare the version-specific score and label relevant to the task. An audit threshold filters only the fetched page; its surviving count is not a global count at that severity.
6. **Before reporting a complete set, finish the requested windows and pages.** Follow pagination notices. For an audit, advance by the upstream rows consumed, including rows dropped by its severity filter, rather than by surviving results alone. A short or empty filtered page does not establish exhaustion.
7. **Before interpreting absent history, confirm the current record.** An empty history can describe an unrevised CVE or an ID NVD does not hold. Use `nvd_get_cve` to distinguish them.

## Core chain

For “does this installed product/version have known vulnerabilities?”, resolve the CPE with `nvd_search_cpes`, disambiguate the returned identity, then call `nvd_audit_cpe`. Review complete pages and configuration evidence before asserting applicability. Retrieve relevant references for advisory and remediation evidence when the task needs them; a matching CVE alone does not establish which fix the installation needs.

For a product version range, derive the match pattern from the resolved CPE identity and preserve that vendor/product identity. Review the returned bounds and configuration prerequisites for the versions actually in scope; a range query is not a separate inventory assessment of each installation.

## Workflows

**Known CVE investigation.** Fetch current details directly when a CVE ID is already known. Use brief results to select records during bulk triage, then fetch full evidence for the conclusions being made. KEV membership supplies catalog evidence of exploitation; absence from KEV does not establish that exploitation is absent. Keep exploit evidence, technical severity, and installation applicability distinct.

**Surveillance.** Choose publication windows for newly published records and modification windows for changed records. Split longer periods into explicit windows no longer than 120 days, page each window, and deduplicate CVE IDs across overlapping boundaries. Inspect any reported date clamping before claiming coverage. Keyword words match together; exact-phrase matching serves a different discovery question. Description terms are not structured product filters.

**Severity coverage.** CVE search matches exactly one severity band at one selected CVSS version. For HIGH-or-worse coverage, query HIGH and CRITICAL separately and deduplicate IDs. If the task requires multiple scoring generations, query those separately too; one generation's filter does not cover records scored only under another. Preserve the version when explaining apparent disagreement between a search result's matched severity and its headline.

**Change investigation.** Fetch history when the question concerns a revision, score change, or status transition. Keep the same ordering while paging: offsets count from the selected end of the history. Compare field-level old/new values with the current record; history events explain changes rather than replacing the current applicability evidence.

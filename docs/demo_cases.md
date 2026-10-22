# Demo cases

Fifteen test-period CVEs for manual inspection, in five groups of three,
pulled through the running API (`/cve/{id}` and
`/watchlist?landmark_day=7`). Each is checked field by field against the
saved corrected-encoding results:

- `data/training/cox_risk_pct.parquet` for the Cox score, `cox_risk_pct`,
  `epss_pct_now` and labels;
- `data/training/fuzzy_priority.parquet` for the fuzzy priority and the
  per-rule firing strengths.

## How the cases were chosen

**Rankings are within the day-7 test pool:** 60,961 test rows at landmark 7,
108 of them KEV-listed after day 7.

- Cox rank uses the same top-k rule as the evaluation
  (`argsort(-partial_hazard)`).
- Budget cut-offs: top 1% = rank ≤ 610, top 5% ≤ 3049, top 10% ≤ 6097.
- "EPSS outside its top 10%" uses the same rule on `epss_pct_now`, which is
  the blind-spot definition.
- **"KEV-listed"** means listed after the day-7 landmark and by the
  2026-09-20 data cutoff.
- **"Never KEV-listed"** means not in KEV at all by the cutoff, which the
  API confirms (`kev: null`).

Within each group, 3 CVEs were drawn at random (seed 20260922, no CVE in two
groups), so these are not hand-picked best or worst cases. Eligible
population per group:

| Group | Definition | Eligible day-7 rows |
|---|---|---|
| **A. True positive** | KEV-listed; Cox top 5% at day 7 | 55 |
| **B. Blind-spot catch** | KEV-listed; EPSS outside its top 10%, Cox inside its top 10% (day 7) | 19 |
| **C. Miss** | KEV-listed; Cox outside its top 10% at day 7 | 42 |
| **D. False alarm** | Never KEV-listed; Cox top 1% at day 7 | 587 |
| **E. True negative** | Never KEV-listed; Cox bottom 50% at day 7 | 30,472 |

**Ranking comes from Cox. The fuzzy priority and its rules are the
explanation, not the ordering.** Cox's survival probabilities are
under-dispersed, so the useful numbers are the percentiles.

## Cases

The landmark columns show `cox_risk_pct / epss_pct_now`, both as
percentiles (%). "—" means no landmark row: the CVE was already KEV-listed
by then, or had no EPSS observation yet.

The rules column lists the rules fired at day 7 with their strength.
ᵉ marks an explanation-only rule (it fires but never moves the score).

| Group | CVE | Published | KEV dateAdded | Days to listing | Cox rank (day 7) | Day 7 | Day 14 | Day 30 | Fuzzy priority (d7 / d14 / d30) | Rules fired (day 7) | API matches saved? |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A. True positive | `CVE-2025-54313` | 2025-07-19 | 2026-01-22 | 187 | 118 (EPSS ranks low) | 99.9 / 19.5 | 99.7 / 19.5 | 99.2 / 4.0 | 74.5 / 74.5 / 79.5 | R01 1.00, R09 1.00, R04 0.28, R12 0.28, R13 0.28 | ✓ yes |
| A. True positive | `CVE-2026-1603` | 2026-02-10 | 2026-03-09 | 27 | 30 | 100.0 / 92.9 | 100.0 / 93.5 | — | 79.5 / 79.5 / — | R01 1.00, R09 1.00, R10 1.00, R11 1.00 | ✓ yes |
| A. True positive | `CVE-2026-24423` | 2026-01-23 | 2026-02-05 | 13 | 1,973 (EPSS ranks low) | 97.1 / 30.8 | — | — | 70.1 / — / — | R01 1.00, R03 1.00, R05 1.00, R09 1.00, R14 1.00, R04 0.78, R12 0.78, R13 0.78, R10 0.22, R11 0.22 | ✓ yes |
| B. Blind-spot catch | `CVE-2025-24472` | 2025-02-11 | 2025-03-18 | 35 | 4,341 (EPSS ranks low) | 92.1 / 11.7 | 88.9 / 11.7 | 88.0 / 11.9 | 79.5 / 79.0 / 78.6 | R01 1.00, R09 1.00 | ✓ yes |
| B. Blind-spot catch | `CVE-2025-34291` | 2025-12-05 | 2026-05-21 | 167 | 1,734 (EPSS ranks low) | 97.6 / 30.6 | 95.9 / 30.7 | 99.8 / 85.3 | 70.0 / 70.0 / 79.5 | R01 1.00, R03 1.00, R05 1.00, R09 1.00, R14 1.00, R04 0.79, R12 0.79, R13 0.79, R10 0.21, R11 0.21 | ✓ yes |
| B. Blind-spot catch | `CVE-2025-53521` | 2025-10-15 | 2026-03-27 | 163 | 3,728 (EPSS ranks low) | 93.0 / 29.1 | 91.2 / 29.1 | 90.6 / 29.1 | 69.7 / 69.8 / 69.7 | R01 1.00, R03 1.00, R05 1.00, R09 1.00, R14 1.00, R04 0.90, R12 0.90, R13 0.90, R10 0.10, R11 0.10 | ✓ yes |
| C. Miss | `CVE-2025-23209` | 2025-01-18 | 2025-02-20 | 33 | 10,986 | 81.0 / 17.8 | 74.7 / 17.8 | 74.3 / 18.0 | 68.8 / 68.0 / 68.0 | R09 1.00, R01 0.16, R04 0.13, R12 0.13, R13 0.13 | ✓ yes |
| C. Miss | `CVE-2025-48384` | 2025-07-08 | 2025-08-25 | 48 | 29,677 | 38.8 / 1.7 | 31.3 / 2.2 | 30.0 / 2.3 | 45.6 / 32.3 / 29.6 | R08 0.58, R09 0.58, R06 0.42, R07 0.42 | ✓ yes |
| C. Miss | `CVE-2025-66376` | 2026-01-05 | 2026-03-18 | 72 | 31,730 | 35.8 / 13.1 | 32.9 / 13.1 | 31.4 / 12.9 | 40.9 / 37.2 / 34.6 | R07 0.55, R06 0.53, R08 0.45, R09 0.45, R15 0.45ᵉ, R17 0.04ᵉ | ✓ yes |
| D. False alarm | `CVE-2025-34115` | 2025-07-15 | — | — | 253 | 99.8 / 71.9 | 99.7 / 71.9 | 99.6 / 71.9 | 79.5 / 79.5 / 79.5 | R01 1.00, R09 1.00, R10 1.00, R11 1.00 | ✓ yes |
| D. False alarm | `CVE-2025-46272` | 2025-04-24 | — | — | 514 (tie of 2: 514–515) | 99.6 / 85.7 | 99.6 / 85.6 | 99.6 / 85.7 | 79.5 / 79.5 / 79.5 | R01 1.00, R05 1.00, R09 1.00, R10 1.00, R11 1.00, R14 1.00 | ✓ yes |
| D. False alarm | `CVE-2026-0773` | 2026-01-23 | — | — | 166 (tie of 4: 166–169) | 99.9 / 81.0 | 99.7 / 81.1 | 99.6 / 78.9 | 79.5 / 79.5 / 79.5 | R01 1.00, R05 1.00, R09 1.00, R10 1.00, R11 1.00, R14 1.00 | ✓ yes |
| E. True negative | `CVE-2025-39891` | 2025-10-01 | — | — | 35,241 (tie of 24: 35,227–35,250) | 27.3 / 8.1 | 21.3 / 8.3 | 20.2 / 8.2 | 33.9 / 30.0 / 30.0 | R07 0.95, R16 0.95ᵉ, R17 0.17ᵉ, R08 0.05, R09 0.05 | ✓ yes |
| E. True negative | `CVE-2025-58903` | 2025-10-14 | — | — | 47,036 | 12.6 / 15.8 | 11.8 / 15.9 | 11.4 / 16.0 | 28.9 / 29.0 / 29.4 | R07 1.00, R17 0.94ᵉ, R06 0.09 | ✓ yes |
| E. True negative | `CVE-2025-7170` | 2025-07-08 | — | — | 34,702 (tie of 7: 34,699–34,705) | 28.4 / 11.4 | 20.7 / 11.4 | 20.8 / 11.2 | 26.7 / 21.5 / 21.3 | R07 0.90, R06 0.80, R17 0.24ᵉ, R08 0.10, R09 0.10, R15 0.10ᵉ | ✓ yes |

## API vs saved results

**15 of 15 cases match on every checked field.** For every
landmark row of each CVE, the checks were:

- **Cox:** partial hazard (relative 1e-9), `cox_risk_pct` and
  `epss_pct_now` (1e-9).
- **Fuzzy:** priority, plus the exact set of fired rules and each rule's
  strength (1e-9).
- **Rows and dates:** the set of scored landmarks and the publication
  date.
- **KEV timing:** days from publication to listing. For groups A–C the API
  value `kev.date_added − published` was checked against the saved label
  `7 + event_time`; for groups D–E the check was `kev: null`.
- **Group membership:** the day-7 Cox rank from `/watchlist`, and the
  `epss_ranks_low` flag for group B, confirm each CVE's group
  independently of the saved files.

**Tied ranks.** Some CVEs have exactly the same Cox score as others: they
are batches of same-day CVEs with identical features. Within a tie block,
rank order is just row position, which differs between the saved file and
the API's pool. So for a tied CVE the API rank can differ from the saved
rank by a few places while both are equally valid. The check is therefore
"API rank lies inside the saved tie block", and the table shows the block.
Across all 60,961 day-7 rows, API and saved Cox scores differ by at most
1.1e-16. (The same arbitrariness applies wherever a budget cut-off falls
inside a tie block in the evaluation.)

## Per-case detail: every landmark's fired rules

**A. `CVE-2025-54313`** (CNA `cve@mitre.org`). eslint-config-prettier 8.10.1, 9.1.1, 10.1.6, and 10.1.7 has embedded malicious code for a supply chain compromise. Installing an affected package executes an install.js file that launches the node-gyp.dll malware on Win…

- day 7: priority 74.5; R01 1.00, R09 1.00, R04 0.28, R12 0.28, R13 0.28
- day 14: priority 74.5; R01 1.00, R09 1.00, R04 0.28, R12 0.28, R13 0.28
- day 30: priority 79.5; R01 1.00, R09 1.00

**A. `CVE-2026-1603`** (CNA `3c1d8aa1-5a33-4ea4-8992-aadd6440af75`). An authentication bypass in Ivanti Endpoint Manager before version 2024 SU5 allows a remote unauthenticated attacker to leak specific stored credential data.

- day 7: priority 79.5; R01 1.00, R09 1.00, R10 1.00, R11 1.00
- day 14: priority 79.5; R01 1.00, R09 1.00, R10 1.00, R11 1.00

**A. `CVE-2026-24423`** (CNA `disclosure@vulncheck.com`). SmarterTools SmarterMail versions prior to build 9511 contain an unauthenticated remote code execution vulnerability in the ConnectToHub API method. The attacker could point the SmarterMail to the malicious HTTP server, …

- day 7: priority 70.1; R01 1.00, R03 1.00, R05 1.00, R09 1.00, R14 1.00, R04 0.78, R12 0.78, R13 0.78, R10 0.22, R11 0.22

**B. `CVE-2025-24472`** (CNA `psirt@fortinet.com`). An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] affecting FortiOS 7.0.0 through 7.0.16 and FortiProxy 7.2.0 through 7.2.12, 7.0.0 through 7.0.19 may allow a remote unauthenticated atta…

- day 7: priority 79.5; R01 1.00, R09 1.00
- day 14: priority 79.0; R09 1.00, R01 0.90, R02 0.10ᵉ
- day 30: priority 78.6; R09 1.00, R01 0.82, R02 0.18ᵉ

**B. `CVE-2025-34291`** (CNA `disclosure@vulncheck.com`). Langflow versions up to and including 1.6.9 contain a chained vulnerability that enables account takeover and remote code execution. An overly permissive CORS configuration (allow_origins='*' with allow_credentials=True)…

- day 7: priority 70.0; R01 1.00, R03 1.00, R05 1.00, R09 1.00, R14 1.00, R04 0.79, R12 0.79, R13 0.79, R10 0.21, R11 0.21
- day 14: priority 70.0; R01 1.00, R03 1.00, R05 1.00, R09 1.00, R14 1.00, R04 0.78, R12 0.78, R13 0.78, R10 0.22, R11 0.22
- day 30: priority 79.5; R01 1.00, R05 1.00, R09 1.00, R10 1.00, R11 1.00, R14 1.00

**B. `CVE-2025-53521`** (CNA `f5sirt@f5.com`). When a BIG-IP APM access policy is configured on a virtual server, specific malicious traffic can lead to Remote Code Execution (RCE).  

Note: Software versions which have reached End of Technical Support (EoTS) are not…

- day 7: priority 69.7; R01 1.00, R03 1.00, R05 1.00, R09 1.00, R14 1.00, R04 0.90, R12 0.90, R13 0.90, R10 0.10, R11 0.10
- day 14: priority 69.8; R01 1.00, R03 1.00, R05 1.00, R09 1.00, R14 1.00, R04 0.90, R12 0.90, R13 0.90, R10 0.10, R11 0.10
- day 30: priority 69.7; R01 1.00, R03 1.00, R05 1.00, R09 1.00, R14 1.00, R04 0.90, R12 0.90, R13 0.90, R10 0.10, R11 0.10

**C. `CVE-2025-23209`** (CNA `security-advisories@github.com`). Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. This is an remote code execution (RCE) vulnerability that affects Craft 4 and 5 installs where your security key has a…

- day 7: priority 68.8; R09 1.00, R01 0.16, R04 0.13, R12 0.13, R13 0.13
- day 14: priority 68.0; R09 1.00, R08 0.15, R04 0.13, R12 0.13, R13 0.13, R15 0.06ᵉ
- day 30: priority 68.0; R09 1.00, R08 0.16, R04 0.14, R12 0.14, R13 0.14, R15 0.07ᵉ

**C. `CVE-2025-48384`** (CNA `security-advisories@github.com`). Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing …

- day 7: priority 45.6; R08 0.58, R09 0.58, R06 0.42, R07 0.42
- day 14: priority 32.3; R06 0.76, R07 0.76, R08 0.24, R09 0.24
- day 30: priority 29.6; R06 0.82, R07 0.82, R08 0.18, R09 0.18

**C. `CVE-2025-66376`** (CNA `cve@mitre.org`). Zimbra Collaboration (ZCS) 10 before 10.0.18 and 10.1 before 10.1.13 allows Classic UI stored XSS via Cascading Style Sheets (CSS) @import directives in an HTML e-mail message.

- day 7: priority 40.9; R07 0.55, R06 0.53, R08 0.45, R09 0.45, R15 0.45ᵉ, R17 0.04ᵉ
- day 14: priority 37.2; R07 0.69, R06 0.54, R08 0.31, R09 0.31, R15 0.31ᵉ, R17 0.14ᵉ
- day 30: priority 34.6; R07 0.76, R06 0.56, R08 0.24, R09 0.24, R15 0.24ᵉ, R17 0.19ᵉ

**D. `CVE-2025-34115`** (CNA `disclosure@vulncheck.com`). An authenticated command injection vulnerability exists in OP5 Monitor through version 7.1.9 via the 'cmd_str' parameter in the command_test.php endpoint. A user with access to the web interface can exploit the 'Test thi…

- day 7: priority 79.5; R01 1.00, R09 1.00, R10 1.00, R11 1.00
- day 14: priority 79.5; R01 1.00, R09 1.00, R10 1.00, R11 1.00
- day 30: priority 79.5; R01 1.00, R09 1.00, R10 1.00, R11 1.00

**D. `CVE-2025-46272`** (CNA `ics-cert@hq.dhs.gov`). WGS-80HPT-V2 and WGS-4215-8T2S are vulnerable to a command injection 
attack that could allow an unauthenticated attacker to execute OS 
commands on the host system.

- day 7: priority 79.5; R01 1.00, R05 1.00, R09 1.00, R10 1.00, R11 1.00, R14 1.00
- day 14: priority 79.5; R01 1.00, R05 1.00, R09 1.00, R10 1.00, R11 1.00, R14 1.00
- day 30: priority 79.5; R01 1.00, R05 1.00, R09 1.00, R10 1.00, R11 1.00, R14 1.00

**D. `CVE-2026-0773`** (CNA `zdi-disclosures@trendmicro.com`). Upsonic Cloudpickle Deserialization of Untrusted Data Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Upsonic. Authentication is not …

- day 7: priority 79.5; R01 1.00, R05 1.00, R09 1.00, R10 1.00, R11 1.00, R14 1.00
- day 14: priority 79.5; R01 1.00, R05 1.00, R09 1.00, R10 1.00, R11 1.00, R14 1.00
- day 30: priority 79.5; R01 1.00, R05 1.00, R09 1.00, R10 1.00, R11 1.00, R14 1.00

**E. `CVE-2025-39891`** (CNA `416baaa9-dc9f-4396-8d5f-8c081fb06d67`). In the Linux kernel, the following vulnerability has been resolved:

wifi: mwifiex: Initialize the chan_stats array to zero

The adapter->chan_stats[] array is initialized in
mwifiex_init_channel_scan_gap() with vmalloc(…

- day 7: priority 33.9; R07 0.95, R16 0.95ᵉ, R17 0.17ᵉ, R08 0.05, R09 0.05
- day 14: priority 30.0; R07 1.00, R16 1.00ᵉ, R17 0.38ᵉ
- day 30: priority 30.0; R07 1.00, R16 1.00ᵉ, R17 0.41ᵉ

**E. `CVE-2025-58903`** (CNA `psirt@fortinet.com`). An Unchecked Return Value vulnerability [CWE-252] in Fortinet FortiOS version 7.6.0 through 7.6.3 and before 7.4.8 API allows an authenticated user to cause a  Null Pointer Dereference, crashing the http daemon via a spe…

- day 7: priority 28.9; R07 1.00, R17 0.94ᵉ, R06 0.09
- day 14: priority 29.0; R07 1.00, R17 0.97ᵉ, R06 0.08
- day 30: priority 29.4; R07 1.00, R17 0.99ᵉ, R06 0.05

**E. `CVE-2025-7170`** (CNA `cna@vuldb.com`). A vulnerability classified as critical was found in code-projects Crime Reporting System 1.0. Affected by this vulnerability is an unknown functionality of the file /registration.php. The manipulation of the argument Nam…

- day 7: priority 26.7; R07 0.90, R06 0.80, R17 0.24ᵉ, R08 0.10, R09 0.10, R15 0.10ᵉ
- day 14: priority 21.5; R07 1.00, R06 0.81, R17 0.51ᵉ
- day 30: priority 21.3; R07 1.00, R06 0.84, R17 0.49ᵉ

## Reading the groups

These are observations about three cases each, not statistics. The
evaluation numbers are in `docs/final_results.md`.

- **A and B** show what the system is for. B in particular shows Cox
  placing a CVE in its top 10% that EPSS left outside its own top 10%.
- **C** shows what Cox misses: KEV-listed CVEs that sat low in the
  ranking at day 7.
- **D** shows the cost: CVEs ranked in the top 1% that were never listed
  by the cutoff. Some could still be listed later, because these are
  censored, not confirmed negatives.
- **E** is the bulk: low-ranked and never listed.

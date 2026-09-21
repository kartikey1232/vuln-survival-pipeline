# Trajectory-Aware Survival Analysis for Early Vulnerability Risk Prediction

A data engineering pipeline that ingests public vulnerability threat intelligence
(NVD, FIRST EPSS, CISA KEV, ExploitDB, MITRE CWE), builds a normalized
PostgreSQL warehouse, reconstructs full EPSS score timelines, engineers
leakage-safe features, and exports a survival-analysis training dataset
(event time, right-censoring, composite event) ready to feed Cox PH, Random
Survival Forest, XGBoost AFT, and Logistic Regression models.

**Status**: data pipeline in active development, module by module. See
`docs/pipeline_stages.md` for the phase plan and current progress.

> Full setup instructions, architecture, and documentation land in
> `docs/` and are completed in the final phase of this build — this README
> is a placeholder until then.

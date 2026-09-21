# models/

Out of scope for this phase of the project.

This directory is reserved for the future modeling phase: training and
serializing the Logistic Regression, Cox Proportional Hazards, Random
Survival Forest, and XGBoost AFT models against the training dataset
produced by `scripts/export/export_training_dataset.py` (see
`training.training_dataset` / `data/training/`).

The database already has a schema-only placeholder for model output —
`training.prediction` — so the modeling phase has a defined target to write
into without any pipeline schema changes.

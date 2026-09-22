# Preliminary Cox PH baseline — PRELIMINARY, UNTUNED

Sanity-check model only, not a candidate for deployment or comparison. Simplification: a CVE contributes up to 3 rows (one per eligible landmark), pooled here as independent observations, which violates the Cox model's independence assumption — see module docstring in `scripts/eda/cox_preliminary.py`.

- Train: n=268944, events=441
- Test: n=178756, events=268
- **Train C-index: 0.8635**
- **Test C-index: 0.8897**

**STOP — test C-index exceeds 0.85, which indicates leakage, not a good model.**

## Coefficients (sorted by p-value)

| covariate                              |         coef |   exp(coef) |    se(coef) |           p |
|:---------------------------------------|-------------:|------------:|------------:|------------:|
| vendor_kev_rate_expanding              |  2.89067     |   18.0053   | 0.676362    | 1.92131e-05 |
| epss_pct_now                           |  0.126817    |    1.13521  | 0.0354894   | 0.000352395 |
| epss_pct_max_to_date                   |  0.106288    |    1.11214  | 0.0323759   | 0.00102732  |
| cvss_base_score                        |  0.00886067  |    1.0089   | 0.00350923  | 0.0115711   |
| epss_pct_7d_ago                        |  0.0668102   |    1.06909  | 0.0344463   | 0.0524348   |
| cwe_kev_rate_expanding                 |  1.747       |    5.73739  | 0.911884    | 0.0553884   |
| exploit_published_by_asof              |  0.208014    |    1.23123  | 0.115988    | 0.0729084   |
| epss_pct_first                         |  0.0558552   |    1.05744  | 0.0373072   | 0.134349    |
| epss_pct_delta_7d                      |  0.132806    |    1.14203  | 0.097869    | 0.174789    |
| user_interaction_NONE                  |  0.0162618   |    1.01639  | 0.0127395   | 0.201783    |
| user_interaction_REQUIRED              | -0.0155546   |    0.984566 | 0.0129104   | 0.228276    |
| integrity_impact_NONE                  | -0.0158558   |    0.984269 | 0.01341     | 0.237052    |
| confidentiality_impact_LOW             | -0.0160622   |    0.984066 | 0.0136506   | 0.239329    |
| privileges_required_NONE               |  0.0128568   |    1.01294  | 0.012099    | 0.28795     |
| integrity_impact_LOW                   | -0.0137128   |    0.986381 | 0.0132715   | 0.301487    |
| confidentiality_impact_NONE            | -0.0147192   |    0.985389 | 0.0142459   | 0.3015      |
| vendor_count                           |  0.00976099  |    1.00981  | 0.00976233  | 0.317377    |
| availability_impact_NONE               | -0.0111812   |    0.988881 | 0.0125319   | 0.372274    |
| availability_impact_LOW                | -0.01358     |    0.986512 | 0.0175533   | 0.43914     |
| privileges_required_LOW                | -0.00914232  |    0.990899 | 0.0125672   | 0.466936    |
| attack_vector_NETWORK                  |  0.00655738  |    1.00658  | 0.0131858   | 0.618974    |
| attack_vector_LOCAL                    | -0.00574419  |    0.994272 | 0.0141321   | 0.684403    |
| cvss_version_3.1                       |  0.0141222   |    1.01422  | 0.0376012   | 0.70723     |
| epss_pct_7d_ago_missing                |  0.00478713  |    1.0048   | 0.0136408   | 0.725632    |
| user_interaction_missing               | -0.0146767   |    0.98543  | 0.0469371   | 0.754516    |
| privileges_required_missing            | -0.0146767   |    0.98543  | 0.0469371   | 0.754516    |
| attack_complexity_missing              | -0.0146767   |    0.98543  | 0.0469371   | 0.754516    |
| attack_vector_missing                  | -0.0146767   |    0.98543  | 0.0469371   | 0.754516    |
| confidentiality_impact_missing         | -0.014645    |    0.985462 | 0.0470902   | 0.755802    |
| cvss_version_missing                   | -0.014645    |    0.985462 | 0.0470902   | 0.755802    |
| integrity_impact_missing               | -0.014645    |    0.985462 | 0.0470902   | 0.755802    |
| cvss_missing                           | -0.014645    |    0.985462 | 0.0470902   | 0.755802    |
| availability_impact_missing            | -0.014645    |    0.985462 | 0.0470902   | 0.755802    |
| landmark_day_30                        | -0.00386455  |    0.996143 | 0.0129446   | 0.765287    |
| attack_complexity_LOW                  |  0.00582642  |    1.00584  | 0.0201392   | 0.772346    |
| landmark_day_7                         |  0.00354263  |    1.00355  | 0.0127701   | 0.78146     |
| attack_vector_PHYSICAL                 | -0.0163021   |    0.98383  | 0.0637719   | 0.798236    |
| cvss_version_3.0                       | -0.0149579   |    0.985153 | 0.0743826   | 0.840625    |
| epss_model_version_at_asof_v2022.01.01 |  0.00245784  |    1.00246  | 0.013251    | 0.85285     |
| epss_model_version_at_asof_v2023.03.01 | -0.00229342  |    0.997709 | 0.0131509   | 0.861557    |
| days_to_first_epss                     |  0.00055127  |    1.00055  | 0.00562327  | 0.921906    |
| days_to_first_exploit                  | -1.59868e-05 |    0.999984 | 0.000193411 | 0.934124    |
| cvss_version_4.0                       | -0.00757054  |    0.992458 | 0.109919    | 0.94509     |
| product_count                          |  8.78328e-06 |    1.00001  | 0.000128123 | 0.945345    |
| attack_vector_ADJACENT_NETWORK         |  0.00203483  |    1.00204  | 0.0336567   | 0.951791    |
| integrity_impact_PARTIAL               | -0.0188982   |    0.981279 | 0.572047    | 0.973646    |
| user_interaction_PASSIVE               | -0.00657256  |    0.993449 | 0.263649    | 0.980111    |
| confidentiality_impact_PARTIAL         | -0.0192837   |    0.980901 | 1.04421     | 0.985266    |
| availability_impact_PARTIAL            | -0.0197311   |    0.980462 | 1.80815     | 0.991293    |

# Which Exploited Vulnerabilities Become Ransomware Targets?

Coursework analysis by **Rakitha Balasuiya**, joining the CISA Known Exploited Vulnerabilities (KEV) catalog to CVE Program records maintained in CVE List V5.

The project asks two questions: can CVE traits predict the time until KEV listing, and can they identify which listed vulnerabilities have known ransomware use? The first apparent result largely disappears after accounting for the catalog's November 2021 launch. The second shows a modest ranking signal that needs stronger validation before operational use.

## Included files

| File | Purpose |
| --- | --- |
| `KEV_Ransomware_Analysis.ipynb` | Analysis, preprocessing, hypothesis tests, models, and saved outputs |
| `data/cisa_kev_catalog.csv` | Retained CISA KEV snapshot |
| `data/kev_cve_enriched_raw.csv` | Joined snapshot: 1,694 records and 39 columns |
| `data/kev_cve_cleaned.csv` | Derived cleaned dataset |
| `build_dataset.py` | Dataset collection and enrichment script |
| `results_summary.json` | Recorded statistics and model results |
| `figures/` | Nine analysis figures |
| `Final_Report.pdf`, `Final_Report.docx` | Written report |
| `requirements.txt` | Pinned numerical/plotting dependencies; Jupyter is unpinned |
| [`presentation/output/KEV_Ransomware_Presentation_Final.pptx`](presentation/output/KEV_Ransomware_Presentation_Final.pptx) | Final editable presentation |
| [`presentation/output/KEV_Ransomware_Presentation.pdf`](presentation/output/KEV_Ransomware_Presentation.pdf) | Presentation PDF |
| [`presentation/output/Speaker_Notes.md`](presentation/output/Speaker_Notes.md) | Delivery notes and examiner questions |

## Recorded results

- Random forest regression CV R² falls from **0.584** across all records to **−0.161** among the 817 CVEs published on or after KEV launch. The target is a shifted log transform of the recorded lag.
- Random forest classification has held-out **ROC-AUC 0.724** and **average precision 0.406**, against a full-dataset known-ransomware rate of **20.8%**.
- At the default threshold, random forest recall is **0.171**; balanced logistic regression recall is **0.600**, with lower precision. These are different operating trade-offs.

These numbers are the retained outputs in `results_summary.json`; publishing the repository does not establish that they have been independently reproduced.

## Run the analysis

Run commands from the repository root. On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m jupyter notebook KEV_Ransomware_Analysis.ipynb
```

Select the environment's Python kernel and run the notebook in order. The notebook uses **seed 42**, an **80/20 split**, five-fold cross-validation, and a stratified classification split. Running it writes the cleaned CSV, figures, and result summary. Numerical library versions can change model results; use the recorded requirements when reproducing the report. The requirements note specifically identifies scikit-learn 1.9 as changing the random forest results.

The committed raw dataset is the analysis snapshot. Rebuilding fetches current CVE records and can change its contents:

```powershell
.\.venv\Scripts\python.exe build_dataset.py
```

The builder refuses to overwrite an existing enriched snapshot. Use `--force` only when deliberately replacing it. It reuses the local KEV catalog when present and otherwise downloads the current catalog; a rebuild is therefore not a reconstruction of immutable historical CVE records.

## Interpretation and limitations

`exploitation_lag_days` is **KEV listing date minus CVE publication date**. It is a proxy for the timing of documented catalog inclusion, not a measured date of first exploitation. Old CVEs necessarily accumulate large lags because the catalog only began in November 2021. Entries listed on or before publication are retained, but those dates alone do not prove zero-day exploitation.

`is_ransomware` maps CISA's `Known` label to 1 and `Unknown` to 0. Unknown does not establish absence of ransomware use. Every row is already in KEV, so this dataset cannot estimate exploitation risk across all CVEs. Detection/reporting bias and right-censoring further limit interpretation.

The current notebook derives imputation values, rare-category groupings, percentile caps, and dummy-variable levels **before the train/test split**. Although scaling is fitted on the training split, other preprocessing uses information from the full sample. Cross-validation also uses those prepared features. The reported scores are exploratory and may be optimistic. Move learned preprocessing into fold-specific scikit-learn pipelines, use temporal evaluation, and check feature availability at prediction time before claiming deployment readiness.

Feature importance is impurity-based and tends to favour continuous/high-cardinality variables. It does not demonstrate causation. Statistical significance is also distinct from a useful effect size. A practical next step is to add non-KEV CVEs, historical EPSS scores, and explicit observation windows.

## Sources

- [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [CISA's KEV data mirror](https://github.com/cisagov/kev-data).
- [CVE Program](https://www.cve.org/) and [CVE List V5](https://github.com/CVEProject/cvelistV5), used by the builder for CVE metadata, CVSS, references, CWE, and CISA ADP/SSVC fields.

Source data remains subject to the respective providers' terms. This repository does not assign a new licence to third-party source records.

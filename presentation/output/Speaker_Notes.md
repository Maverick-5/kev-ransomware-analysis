# KEV presentation speaker notes

Presenter: Rakitha Balasuiya

Target talk: 10 minutes 30 seconds, excluding questions. Slides 1–5: 3:00; slides 6–9: 4:05; slides 10–13: 3:25.

## 1. Title (25 seconds)

This project asks which vulnerabilities that are already known to be exploited become linked to ransomware. I joined the CISA KEV catalogue to CVE records and tested two questions: how quickly a CVE reaches KEV, and whether a listed CVE is associated with ransomware. The clearest finding is a failure: the original speed model was learning a calendar artefact.

The title uses the requested wording. Throughout the talk, ransomware means the CISA Known ransomware-use label at the collection snapshot. This is a retrospective study, not a deployed forecasting service.

Sources: results_summary.json; KEV_Ransomware_Analysis.ipynb

## 2. Why it matters (30 seconds)

CVSS describes technical severity. Defenders also need evidence about attacker behaviour and urgency. CISA KEV is useful because inclusion requires evidence of exploitation in the wild. That makes it a strong source of observed positive cases. It is still incomplete, and its date-added field tells us when CISA listed a vulnerability, not when the first attack happened. That distinction becomes central to the result.



Sources: FIRST CVSS v3.1 user guide: https://www.first.org/cvss/v3.1/user-guide ; CISA KEV mirror: https://github.com/cisagov/kev-data

## 3. Two questions (25 seconds)

Question one is regression: can ordinary CVE traits predict the delay from publication to KEV listing? Question two is classification: among already-exploited CVEs, can those traits distinguish known ransomware links? These are separate targets and separate models. One apparent success disappears when the catalogue history is taken seriously. The other retains a modest ranking signal.



Sources: results_summary.json; KEV_Ransomware_Analysis.ipynb

## 4. Dataset (40 seconds)

The join produced 1,694 unique CVEs with 39 raw columns and 283 vendors. The identifier years run from 2002 to 2026; actual publication dates begin in April 2003. The regression target subtracts CVE publication from KEV listing. The classification target treats CISA Known ransomware use as positive: 352 records, or 20.8 percent. The remaining records are not confirmed negatives; they have no known link in this snapshot. Every row is already a KEV positive for exploitation.

If asked about coverage: publication dates are 2 April 2003 to 1 September 2026; KEV date-added dates are 3 November 2021 to 2 September 2026. Counts were checked against data/kev_cve_enriched_raw.csv.

Sources: results_summary.json; KEV_Ransomware_Analysis.ipynb

## 5. Cleaning and preprocessing (60 seconds)

A missing vector does not mean low severity. Vectors are absent for 317 records, or 18.7 percent, and missingness is strongly associated with CVE age. I retain a NOT_ASSESSED category rather than discard those records. Missing numeric scores are separate: 62 were median-imputed. Rare vendor and weakness levels are grouped as OTHER. Explicit target-derived fields are excluded. The matrix has 64 features and uses an 80/20 split with seed 42. There is a validation limitation: the notebook fits some imputation and category decisions before splitting, and scales outside cross-validation folds. The next version should fit all learned preprocessing inside each training fold.

Do not call the 212 records proven zero-days: 59 are listed before publication and 153 on the same day. Do not say the study establishes a formal missing-not-at-random mechanism. The missingness test is a Mann–Whitney comparison by CVE ID year, p = 1.534e-62. The pipeline diagram summarises stages; it does not claim safe fitting order.

Sources: results_summary.json; KEV_Ransomware_Analysis.ipynb

## 6. What the data looks like (55 seconds)

The lag distribution has a spike near publication and a long backlog. There are 212 records listed by publication day, 190 more listed one to seven days later, and 782 listed after a year. The cumulative within-a-week count is 402, so do not add 212 to it again. The clipped histogram makes the far tail visible as a pile-up at 1,500 days; that is a display cap, not the true maximum. Microsoft contributes 386 records, or 22.8 percent of KEV. This is a catalogue share. Without a denominator of installed products or vulnerabilities, it cannot estimate a vendor defect rate. Install base is a possible explanation, not something tested here.

The original histogram and vendor panel are selected from the requested source figures without changing plotted observations. The original source figure calls lag<=0 zero-day; the presentation uses the narrower date-based description.

Sources: results_summary.json; KEV_Ransomware_Analysis.ipynb

## 7. The calendar artefact (100 seconds)

This is the key slide. On the left, publication year and lag look almost perfectly related: the correlation is minus 0.916. It is tempting to treat that pattern as attacker behaviour. But the catalogue did not exist before 3 November 2021. The target is date added minus publication date. A CVE published years before the catalogue opened therefore starts with years of unavoidable delay. Imagine a CVE published in 2010 and added at launch: it has an eleven-year lag even if exploitation had been known much earlier. An equally serious CVE published in 2022 can enter with only days of delay. The metric contains the catalogue history by arithmetic. Now look right. Restricting the sample to the 817 CVEs published on or after launch removes the pre-launch backlog. The correlation falls to minus 0.293. The remaining wedge may still reflect shorter observation windows for recent CVEs and listing practices. This correction does not prove attack speed is inherently unpredictable. It shows that this proxy is contaminated, and the broad-sample performance cannot be read as forecasting skill.

Delivery: spend about 100 seconds here. Point to the left diagonal, explain the subtraction with the 2010 example, pause, then point to the right cloud. Examiner: "Why drop rows before 2021?" Answer: I did not delete them from the source data or classifier; I ran a sensitivity analysis for Q1 using the exact launch cutoff, 3 November 2021. Older records remain useful for describing KEV and ransomware labels.

Sources: figures/kfig3_artefact.png; results_summary.json r_lag_year_all/r_lag_year_sub; notebook cell 37; CISA KEV mirror: https://github.com/cisagov/kev-data

## 8. Hypothesis tests (45 seconds)

The tests ask whether the groups differ, not whether a classifier will be useful. Ransomware-linked records have a mean CVSS score only 0.275 points higher. The Welch test is statistically significant at p 0.00048, but Cohen d is just 0.21 and the densities overlap strongly. Automatability is also associated with the ransomware label: 25.7 versus 17.5 percent, with odds ratio 1.64. Yet Cramér V is only 0.098. The Kruskal–Wallis test for lag across severity bands is not rejected at p 0.063. With enough observations, a small difference can pass a significance test and still provide little individual discrimination.

More detail if asked: Welch t=3.515; means 8.577 vs 8.302. Chi-square=16.29, p=5.4336e-5, odds ratio=1.635. Kruskal H=5.533, epsilon squared=0.0065. These results do not establish causality or a formal superiority comparison between automatability and CVSS.

Sources: results_summary.json; KEV_Ransomware_Analysis.ipynb

## 9. Q1 result (45 seconds)

The modelling result follows the artefact. Random forest has cross-validated R squared of 0.584 on all records, which initially looks useful. On the post-launch subset it is minus 0.161. Linear regression and gradient boosting are also negative there. None of the tested models beats the mean benchmark for this transformed listing-delay target. Calendar and date variables were excluded as predictors, so I cannot claim the forest literally read a start-date feature. The safer explanation is that the broad-sample model exploited traits associated with backlog and CVE era. This is a useful negative result: checking the target changed the conclusion.

Metric detail: the notebook models log1p(exploitation_lag_days + 291), not raw days. All-record CV R²: linear 0.4671, RF 0.5838, GB 0.5481. Post-launch: −0.1718, −0.1607, −0.1651. The sensitivity analysis changes sample composition and does not isolate every causal explanation.

Sources: results_summary.json; KEV_Ransomware_Analysis.ipynb

## 10. Q2 result (70 seconds)

The ransomware classifier retains a modest signal. Random forest has test ROC-AUC 0.724. That describes ranking across thresholds; it is not 72.4 percent accuracy. The precision–recall summary is average precision, reported as PR-AUC in the project: 0.406 against a catalogue positive rate near 0.208. It is roughly twice that random baseline in average precision, not guaranteed double precision at one threshold. At the default 0.5 threshold, the saved forest catches only 12 of the 70 labelled positives: recall 0.171, with precision 0.462. Logistic regression trades more alerts for recall 0.600. Forest accuracy is 78.8 percent, slightly below the 79.4 percent achieved by predicting no ransomware link for everyone in this test set. I would use the ranking as a research lead, not an automatic operational decision.

Examiner: "Why is recall low?" The saved forest uses the default 0.5 decision threshold; the imbalanced sample and fitted scores produce few positive calls. A lower threshold may improve recall but must be selected on validation data against an alert budget, not tuned on the final test set. Logistic regression also uses balanced class weights, so its higher recall is not a pure threshold-only comparison. "Is AUC 0.724 good?" Modest discrimination, limited by retrospective sampling, unknown labels and validation design. No confidence interval or prospective evaluation was established.

Sources: results_summary.json classification; notebook average_precision_score and test confusion matrix; figures/kfig8_classifier.png

## 11. Feature importance (45 seconds)

The top forest features are description length, reference count and CVSS score. That suggests metadata contains signal beyond severity alone. But this plot is impurity importance, which favours continuous and high-cardinality predictors. It cannot show that writing a longer description causes ransomware adoption. There is a more serious timing caveat: these features were collected in September 2026. A well-documented vulnerability may have accumulated references after exploitation or ransomware use. That possible look-ahead makes this a retrospective association. A prospective model needs features frozen at the prediction date.

Saved importances: description word count 0.1646; reference count 0.1131; CVSS base score 0.0922. Next checks: fit preprocessing within folds; freeze metadata at prediction time; assess held-out permutation importance and a chronological split. Do not report these as completed checks.

Sources: results_summary.json; KEV_Ransomware_Analysis.ipynb

## 12. Conclusions and limitations (65 seconds)

The first conclusion is methodological: severity alone does not describe attacker behaviour, and a date-derived target can manufacture apparent predictability. The second is narrower: among KEV entries, the saved ransomware classifier has modest ranking value, and automatability has a small association with the label. This is consistent with considering exploitation and context, as SSVC and EPSS do. It does not validate either framework. EPSS predicts exploitation in the next 30 days, which is a different target from ransomware adoption. The limits are substantial: there are no non-exploited controls, unknown ransomware use is treated as negative, recent CVEs have shorter follow-up, and observation depends on detection and reporting. Metadata may be measured after the outcome, and learned preprocessing needs proper isolation. The next study should add non-exploited CVEs, use dated EPSS and timestamped features, and evaluate future periods with preprocessing fitted inside training folds.

Examiner: "Can this predict all vulnerabilities?" No. The study conditions on already being in KEV. "Does Not Known mean no ransomware use?" No; absence of a known link is an uncertain label. "Why does the corrected lag still have structure?" Right-censoring and listing/detection processes remain.

Sources: results_summary.json; notebook limitations; FIRST EPSS: https://www.first.org/epss/ ; CISA SSVC guide: https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf

## 13. Questions and links (25 seconds)

The repository contains the notebook, dataset, figures and saved results behind this presentation. The analysis uses seed 42 and pins the main analysis packages, including scikit-learn 1.8.0. The saved analysis is version-sensitive; pinning packages helps, but a full runtime definition still matters. The contribution is the calendar-artefact diagnosis and an honest assessment of a weak ransomware ranking model. I am happy to discuss the launch cutoff, the recall trade-off or the next validation design.

Reproducibility boundary: six analysis libraries are pinned; Jupyter and the Python runtime are not fully specified. The requirements comment reports changed forest behaviour in scikit-learn 1.9. A seed alone does not guarantee bit-for-bit reproduction. Repository visibility is private unless changed by the owner.

Sources: Project repository: https://github.com/Maverick-5/kev-ransomware-analysis; CISA: https://github.com/cisagov/kev-data ; CVE Program: https://github.com/CVEProject/cvelistV5 ; requirements.txt

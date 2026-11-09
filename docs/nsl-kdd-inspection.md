# NSL-KDD dataset inspection and preparation plan

**Status:** Inspection only; model training has not been performed.

## Files and format

Both expected files are present in `data/`:

- `KDDTrain+.txt`
- `KDDTest+.txt`

They are comma-delimited, headerless files. Each row has 43 columns: the first 41 are network traffic features, column 42 is the original attack label, and column 43 is the difficulty level. The files contain 125,973 training records and 22,544 test records, respectively.

| File | Records | Columns | Normal | Attack | Distinct labels |
|---|---:|---:|---:|---:|---:|
| `KDDTrain+.txt` | 125,973 | 43 | 67,343 (53.46%) | 58,630 (46.54%) | 23 |
| `KDDTest+.txt` | 22,544 | 43 | 9,711 (43.08%) | 12,833 (56.92%) | 38 |

The test set contains 17 attack labels absent from the training set. This is relevant to the binary task: these labels can still be mapped to “attack,” but results should also be interpreted as evaluation on unseen attack types.

## Feature schema

The files contain the canonical 41 NSL-KDD traffic features in this order:

1. `duration`
2. `protocol_type`
3. `service`
4. `flag`
5. `src_bytes`
6. `dst_bytes`
7. `land`
8. `wrong_fragment`
9. `urgent`
10. `hot`
11. `num_failed_logins`
12. `logged_in`
13. `num_compromised`
14. `root_shell`
15. `su_attempted`
16. `num_root`
17. `num_file_creations`
18. `num_shells`
19. `num_access_files`
20. `num_outbound_cmds`
21. `is_host_login`
22. `is_guest_login`
23. `count`
24. `srv_count`
25. `serror_rate`
26. `srv_serror_rate`
27. `rerror_rate`
28. `srv_rerror_rate`
29. `same_srv_rate`
30. `diff_srv_rate`
31. `srv_diff_host_rate`
32. `dst_host_count`
33. `dst_host_srv_count`
34. `dst_host_same_srv_rate`
35. `dst_host_diff_srv_rate`
36. `dst_host_same_src_port_rate`
37. `dst_host_srv_diff_host_rate`
38. `dst_host_serror_rate`
39. `dst_host_srv_serror_rate`
40. `dst_host_rerror_rate`
41. `dst_host_srv_rerror_rate`

The three categorical features are `protocol_type`, `service`, and `flag`. Both files contain the protocols `icmp`, `tcp`, and `udp`, and 11 flag values: `OTH`, `REJ`, `RSTO`, `RSTOS0`, `RSTR`, `S0`, `S1`, `S2`, `S3`, `SF`, and `SH`. There are 70 distinct services in training and 64 in testing; no test service value is absent from training.

The other 38 traffic features are numeric. They include counts and byte totals, binary indicators, and rate features. The 15 rate features are stored between 0 and 1 in both files. The difficulty column is an integer metadata field with values from 0 through 21; it is not one of the 41 traffic features.

## Labels and attack categories

Use the literal `normal` label for the benign class. The training file has 22 attack labels:

`back`, `buffer_overflow`, `ftp_write`, `guess_passwd`, `imap`, `ipsweep`, `land`, `loadmodule`, `multihop`, `neptune`, `nmap`, `perl`, `phf`, `pod`, `portsweep`, `rootkit`, `satan`, `smurf`, `spy`, `teardrop`, `warezclient`, `warezmaster`.

The test file includes those labels and these 17 additional attack labels:

`apache2`, `httptunnel`, `mailbomb`, `mscan`, `named`, `processtable`, `ps`, `saint`, `sendmail`, `snmpgetattack`, `snmpguess`, `sqlattack`, `udpstorm`, `worm`, `xlock`, `xsnoop`, `xterm`.

## Data-quality findings

- Every row in both files has 43 columns; no malformed rows were found.
- No blank cells, non-numeric values in numeric fields, or negative numeric values were found.
- No exact duplicate rows were found within either file.
- `num_outbound_cmds` is constant at zero in both files.
- `su_attempted` takes values `0`, `1`, and `2` (59 training rows and 2 test rows contain `2`). Do not assume it is strictly binary or reject `2` as malformed. `num_shells` also takes values `0`, `1`, and `2`.
- There are 610 exact full records shared between the train and test files. At the feature-vector level, 654 distinct vectors are shared; 51 of those have conflicting binary normal/attack targets between splits. This is an evaluation caveat, not a reason to silently alter the supplied test set. Preserve the official split and report the overlap; consider a separately identified overlap-excluded sensitivity result.

## Proposed preprocessing pipeline

1. Read the files without headers and assign a single, explicit schema for the 41 ordered features, the original label, and difficulty. Validate row width and types before transformation.
2. Keep the original label as separate metadata (`attack_label`). Derive the binary target as `0` only for `normal` and `1` for every non-empty non-`normal` label. This retains attack names for later class-specific analysis without passing labels to the model.
3. Exclude both the original label and the difficulty column from model inputs. Difficulty is dataset metadata and is unavailable for ordinary inference; including it would create leakage.
4. One-hot encode `protocol_type`, `service`, and `flag`. Use an encoder that ignores unknown categories at transform time. Fit the encoder on training data only.
5. Parse the remaining features as numeric. No scaling is needed for the planned Random Forest. No imputation is required by the inspected files; reject or explicitly handle missing values if future inputs contain them. If imputation is later introduced, fit it on training data only and include it in the saved pipeline.
6. Keep the official test file untouched for final evaluation. Use validation splits drawn only from the training data for model selection. Report the official test result together with the feature-overlap caveat above.
7. Bundle the fitted preprocessing and estimator in one serialized pipeline. At inference, validate the same 41 feature names and order, apply the same transformations, and do not require a target or difficulty value.

## Files proposed for the training stage

These are planning recommendations only; none have been created as part of this inspection.

- `backend/ml/schema.py` — canonical feature names, column types, and label/difficulty positions.
- `backend/ml/dataset.py` — CSV loading, schema validation, and binary-target derivation while retaining original labels separately.
- `backend/ml/preprocessing.py` — training-fitted categorical and numeric transformations assembled as a scikit-learn pipeline.
- `backend/ml/train.py` — Random Forest baseline training using `KDDTrain+.txt`.
- `backend/ml/evaluate.py` — evaluation against `KDDTest+.txt`, including binary metrics and analysis by original attack label.
- `backend/tests/test_dataset.py` and `backend/tests/test_preprocessing.py` — schema, label mapping, unknown-category, and train/inference consistency tests.
- `backend/ml/artifacts/` — generated model pipeline and metadata; keep generated model artifacts out of version control.

The training stage will need scikit-learn and joblib in addition to the current backend dependencies. Pandas may be added if it is useful for data analysis, but the inspected CSV format can also be loaded with Python's standard `csv` module.

## Scope and current project state

The backend currently contains the Flask app factory, configuration, runner, health test, and requirements. There is no existing ML loader, preprocessing pipeline, model, or ML test code. This inspection made no changes to the Flask application and did not install dependencies or train a model.

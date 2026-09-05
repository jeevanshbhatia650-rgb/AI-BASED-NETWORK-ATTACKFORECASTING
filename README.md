# Infiltration Prediction Engine (Step 4)

**PS153 — AI-Based Network Attack Forecasting via World Models**
Module owner: Prediction Engine & Attack-Stage Mapping

This module takes the one-step predictions from the World Model
(`P(S_t+1 | S_t)`) and rolls them forward K steps to forecast whether
a network is heading toward compromise — before it completes — then
maps each forecasted state onto a MITRE ATT&CK stage.

It is fully self-contained and does **not** depend on the real
trained LSTM. It runs against `MockWorldModel`, a stand-in that
simulates plausible next-states, so this module can be built, tuned,
and demoed independently while World Model Development finishes the
real checkpoint. Swapping in the real model later is a one-line
change (see [Swapping in the real model](#swapping-in-the-real-model)).

## Files

| File | Purpose |
|---|---|
| `infiltration_engine.py` | Core module: rollout, risk scoring, stage mapping, main pipeline |
| `tune_thresholds.py` | Grid-searches rule thresholds / blend weight against labelled scenarios |
| `horizon_experiment.py` | Finds the optimal forecast horizon K and drafts the architecture-doc paragraph |
| `data_pipeline.py` | Ingests classic PCAP or JSONL network logs and produces the normalised 19-feature vectors/windows required by the model |

## Quick start

```bash
pip install numpy matplotlib
python3 infiltration_engine.py     # self-test: runs all demo scenarios + windowed rollout check
python3 tune_thresholds.py         # grid search over rule_weight / alert_threshold
python3 horizon_experiment.py      # multi-scenario K stability sweep + draft paragraph
```

## How it works

```
Current Network State Window [S_(t-W) ... S_t]
                       |
                       v
         +-----------------------------+
         |  World Model (LSTM/RNN)     |
         +-----------------------------+
                       |
                       v
          Predicts Next State S_(t+1)
                       |
        +--------------+--------------+
        |                             |
        v                             v
[Feedback Loop:               [Risk Scoring Head]
 Append S_(t+1) to input,              |
 repeat K times]                       v
        |                      Calculate Infiltration
        |                      Probability P(t+1)
        v                              |
 Simulates S_(t+2) ... S_(t+K)         v
                               Output Probability Timeline
                               for UI (t+1 through t+K)
```

1. **Autoregressive rollout** (`predict_rollout` / `predict_rollout_windowed`) — feeds each predicted state back into the model K times.
2. **Risk scoring** — each simulated state gets a probability from two signals blended together:
   - **Rule-based**: hand-written thresholds on features (port scan rate, beacon periodicity, etc.) map a state to a MITRE ATT&CK stage and strength.
   - **Baseline deviation** (`BaselineDeviationScorer`): Mahalanobis distance from a learned "normal traffic" baseline, squashed to `[0, 1]`.
   - Combined via `rule_weight` (default `0.5` — see [Tuning results](#tuning-results)).
3. **Output**: a probability timeline (`t+1` → `t+K`) plus the predicted ATT&CK stage, ready to hand to the dashboard.

## Feature schema

19 normalised features (roughly `[0, 1]`, higher = more suspicious), defined in `FEATURE_NAMES` — flag counts, byte/packet volumes, flow duration, inter-arrival-time stats, port-scan signals, and C2/lateral-movement indicators. See the top of `infiltration_engine.py` for the full list. **This is the contract Data & Feature Engineering's output must match.**

## Data ingestion pipeline

`data_pipeline.py` supplies the missing upstream data layer. It reads either:

- classic Ethernet/IPv4 `.pcap` captures (TCP and UDP metadata), or
- JSON Lines packet/flow events from firewall, Suricata, or Zeek-style logs.

It canonicalises each input into a packet record, groups records into fixed
source-IP observation windows (60 seconds by default), calculates the 19 raw
features, applies a bounded min-max normalisation, and writes JSON Lines. Use
`--sequence-size T` to produce `model_window` arrays shaped `(T, 19)` for the
windowed world-model contract.

```bash
python data_pipeline.py pcap traffic.pcap --output feature_rows.jsonl
python data_pipeline.py jsonl network_events.jsonl --window-seconds 60 --sequence-size 10 --output model_windows.jsonl
python -m unittest test_data_pipeline.py
```

The supplied normalisation scales are safe starting caps, not learned values.
Before deployment, profile benign traffic and tune the scales (or replace the
bounded transform with a persisted training-set scaler) so training and
inference use exactly the same transform.

## Usage

```python
from infiltration_engine import predict_infiltration, MockWorldModel, BaselineDeviationScorer

scorer = BaselineDeviationScorer().fit_default()   # swap for .fit(real_benign_states) later
model = MockWorldModel(seed=42)                     # swap for the real LSTM adapter later

result = predict_infiltration(
    initial_state,          # np.ndarray, shape (19,)
    k=7,                    # forecast horizon — see horizon_experiment.py for why 7
    model=model,
    deviation_scorer=scorer,
)

result["timeline"]                    # per-step: probability, stage, triggered_rules, state
result["max_probability"]             # highest probability anywhere in the rollout
result["peak_stage"]                  # stage label at the highest-probability step — USE THIS
result["overall_infiltration_flag"]   # True if max_probability crosses alert_threshold
```

> **Use `peak_stage`, not `final_stage`, as the displayed prediction.** `final_stage` reflects only the last simulated step and can drift back toward "Benign" on noise even after the trajectory clearly spiked mid-rollout — misleading on a dashboard or in the demo video.

## Tuning results

Grid-searched `rule_weight` (rule-based vs. baseline-deviation blend) and `alert_threshold` against six labelled synthetic scenarios (one per ATT&CK stage + benign). **Recommended and shipped as defaults: `rule_weight=0.5`, `alert_threshold=0.6`** — 100% stage accuracy, 100% alert correctness, and a clean separation between benign (~0.00) and the weakest attack (~0.68). Pure-deviation scoring scores marginally higher on separation alone but was rejected: it discards the rule-based signal entirely, which contradicts the architecture doc's "combine rules + baseline distance" design.

Re-run `tune_thresholds.py` any time the rule thresholds or scenario definitions change.

## Horizon (K) selection

Ran the autoregressive rollout 20 times per horizon across 5 attack trajectories, sweeping `K ∈ {3, 5, 7, 10, 15}`, and measured how much the predicted final state varied across runs (compounding error).

> To choose the forecast horizon K, we ran the autoregressive rollout 20 times per horizon across 5 representative attack trajectories (Reconnaissance, Initial Access, Lateral Movement, Command & Control, Exfiltration), sweeping K over (3, 5, 7, 10, 15), and measured how much the predicted final state varied across runs at each horizon (compounding error). Mean variance rose from 0.0011 at K=3 to 0.0056 at K=15 — roughly a 5.1x increase — confirming that prediction uncertainty compounds as expected with autoregressive feedback. We selected K=7 as the forecast horizon, the largest tested value where mean variance stays low (0.0027) while still giving defenders a meaningful lead window before predicted compromise.

Re-run `horizon_experiment.py` any time scenarios or the model change — this paragraph is generated from live output, not hand-written.

## Swapping in the real model

Two possible contracts — confirm with World Model Development which one their checkpoint uses:

- **Single-state**: `predict(state) -> next_state` → use `predict_rollout()` (default path, no changes needed)
- **Windowed**: `predict(window) -> next_state`, `window.shape == (W, N_FEATURES)` → use `predict_rollout_windowed()`

Either way, fill in `LSTMWorldModelAdapter` in `infiltration_engine.py` and change one line:

```python
model = MockWorldModel(...)                       # before
model = LSTMWorldModelAdapter(checkpoint_path)     # after
```

Nothing downstream (stage mapping, dashboard, explainability) needs to change.

## Known limitations

- Tuning and K selection above are calibrated against **synthetic scenario data + the mock model**, not real CIC-IDS-2018/CTU-13 traffic or the real trained LSTM. Re-run both scripts once the real checkpoint and real benign-traffic baseline are available — cheap sanity check, not new work.
- `BaselineDeviationScorer.fit_default()` is a placeholder (zero-mean, low-variance). Swap for `.fit(real_benign_states)` as soon as Data & Feature Engineering hands off a normalised feature matrix.
- Rule thresholds in `DEFAULT_RULE_THRESHOLDS` are starting points; tune further once real labelled attack data is available.

## For teammates integrating this module

- **Demo Interface (Streamlit)**: call `predict_infiltration(...)`, render `result["timeline"]` and `result["peak_stage"]`. Output shape is stable — safe to build against now.
- **Explainability**: attach SHAP/attention scores per `timeline[i]["state"]`.
- **Data & Feature Engineering**: confirm your output matches `FEATURE_NAMES` order/normalisation.

# Verification record

Initial verified platform: Linux, Python 3.10, local Chromium. These are actual executed checks, not assumed compatibility.

- 32 unittest methods passed, including 60 valid parser subcases and invalid/unsafe subcases.
- Browser smoke passed: dashboard, preview/apply, policy registry update, confirmed link fault, flow explorer, rollback, unsafe-intent rejection, separate-browser isolation, 390px mobile no horizontal overflow. No browser page errors.
- Desktop/mobile interface screenshots were rendered from actual backend state and visually inspected.
- Model comparison ran 10 trials of 30 post-failure steps per mode at high demand. Exact synthetic results in model-evaluation.json. Forecast-aware heuristic underperformed reactive-only on this workload; no claim of universal improvement.
- Fixed-baseline walk-forward five-step forecasts evaluated on 85 held-out synthetic samples; these are not real-traffic or trained-LSTM results.

Not verified: Windows/macOS execution, real packets, Ryu/Mininet/OpenFlow, trained LSTM, physical-network recovery and Google API availability at all future times. Docker image built and deployed on Render using Python 3.12, with all 32 unittest methods passing during the hosted build. Live deployment and current API verification are recorded in deployment.md.

Reproduce with python -m unittest discover -s tests -v, python tests/evaluate.py and the optional Playwright browser_smoke.py.

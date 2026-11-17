# Deployment record

Verified 17 November 2026, UTC.

- Live app: https://aether-network-twin.onrender.com/
- Private source: https://github.com/instinctsetup/aether-network-twin
- Hosting: Render Free, Docker, Python 3.12. No payment method or paid instance selected.
- Initial hosted Docker build passed all 32 unittest methods. Local Chromium checks passed nine workflow checks with zero page errors.
- A live browser manually verified a proposal, explicit approval, revision increment and actual backend enforcement: video priority and blocked p2p delivery of zero.
- Automated live QA exposed a fast-click race in the initial UI: approval could be clicked before the proposal request's refresh finished. Fixed by disabling approval until that operation completes. The final live test record is stored alongside this file after redeployment.

## Model and safety limits

The network is a synthetic, isolated digital twin. No physical switches, Mininet, Ryu, real OpenFlow traffic or trained LSTM experiment was run. The in-app labels, model documentation and exported evidence preserve this distinction.

The forecast-aware heuristic underperformed reactive-only routing in the included high-demand synthetic failure comparison. See MODEL.md and model-evaluation.json for the exact workload and results. No general performance gain is claimed.

Gemini was used for architecture and code review during development. Claude access did not produce a usable response. The app's optional Gemini adapter uses a server-only key, a free-tier confirmation gate and bounded quotas. Early generation requests to current free Google models returned HTTP503; offline mode remains fully functional and is explicitly labeled as a non-LLM compiler. Server configuration does not prove provider availability.

## Free hosting limits

Render Free can sleep after 15 idle minutes. A cold visit may take 50 seconds or more. Sessions and the local quota database are ephemeral and can reset after restart or redeploy. Free limits are shared across the workspace. The SQLite daily call cap is instance-local, not a durable billing guard. The Google project must remain unbilled; no paid-provider fallback is implemented. See https://render.com/docs/free and https://ai.google.dev/gemini-api/docs/pricing .

The source repository remains private. A write-collaborator invitation was sent to ursthakurmahesh and was pending at verification. Accept the invitation while signed into that account to access the source.

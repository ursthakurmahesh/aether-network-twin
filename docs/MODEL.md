# Model and architecture

## Closed loop
Browser -> POST /api/propose -> offline compiler or Gemini -> canonical schema -> safety/conflict/route checks -> cloned-model dry run -> explicit approval -> revision check -> policy commit -> one-second model steps -> flow/queue estimates -> forecast-aware or reactive path recomputation -> audit trace. Rollback restores control configuration, not wall-clock time.

## Topology and workload
Two spine and four leaf switches, eight attached hosts, eleven switch links. Edges have configured capacities of 20/40/100 Mbps and 2-4 ms one-way propagation. Host access links are abstract attachments with no independent modeled bottleneck. A fixed workload has video, web, voice, p2p and DNS flows. At tick t, requested demand is base_demand * demand_multiplier * (1 + 0.15*sin(t/8 + flow_index)). This creates reproducible variation, not sampled real-world traffic.

## Routing
Dijkstra over operational links, with lexicographic path tie-breaks. Explicit reroute waypoints and avoided links constrain the route. For forecast mode, edge cost includes 20*max(forecast_utilization,current_utilization)^3. Latency-matched flows add the bounded queue-delay estimate to their edge cost independently of forecast mode. A valid old route is retained unless the candidate is at least 15% cheaper and a five-step hold-down has elapsed. Broken paths bypass these stabilizers. A latency violation can bypass the hold-down. This is a small deterministic heuristic and can move multiple flows onto the same alternate route. It is not optimal traffic engineering.

Reactive mode recomputes routes within a model step. No real recovery duration is claimed. The static baseline keeps its broken path with zero delivery on that flow; it is not an OSPF implementation. OpenFlow fast-failover groups are not used.

## Flow accounting
Blocked traffic is accounted before admission and is not called congestion loss. Matching aggregate rate-limit rules have shared per-step Mbps budgets, consumed across their matching flows. Shaped traffic is accounted separately. Non-blocked, non-shaped traffic is offered to the modeled fabric.

Flows with priority policies are scheduled first, then others; flow ID breaks ties. For each flow, delivered Mbps = min(offered Mbps, residual capacity of every link in its path). Unreachable paths deliver zero. Each used link is charged only the delivered flow bandwidth. Drops = offered - delivered. Demand = blocked + shaped + offered, with floating-point tolerances. Each edge's load never exceeds its capacity. Link capacity is conservatively shared in both directions rather than full-duplex independent directions.

This steady-state fluid model is not a packet simulator: it does not track TCP state, retransmissions, buffers, individual packet timing, packet counts, real jitter or physical-layer effects. An upstream oversubscribed path does not incur per-hop wasted bandwidth. Strict scheduling may starve later flows. Allow is an explicit policy declaration; it does not override conflicting block rules.

## Telemetry and forecasting
Utilization = allocated Mbps / capacity Mbps. Queue-delay estimate per link = 0.2*rho/max(0.05,1-rho) ms. RTT estimate = twice the sum of one-way propagation and queue-delay estimates along a flow path. Jitter estimate is an illustrative 3% of RTT, not a measured statistic. A flow's latency SLA is checked against the actual modeled RTT after all flow allocation. Admission rejects impossible propagation-only limits but cannot guarantee a queue-sensitive SLA. If no route meets an SLA, the best available route is kept and the flow is marked in violation.

Forecast = clamp(mean(last eight utilization samples) + 5*(last-first)/(sample_count-1),0,2). The 5-step horizon is five model seconds, not a wall-clock prediction guarantee. It is a moving-average/trend baseline, not trained LSTM or ARIMA. The included chronological evaluation tests fixed baselines on a synthetic analytical utilization series, not real collected traces. It honestly reports when forecast-aware routing loses to reactive-only routing.

## State and safety
Control revision increments on policy commit, rollback, administrative link change or settings change. Telemetry ticks do not change it. Proposals expire after ten minutes and bind to the current control revision. Stored proposals are deep copies. Approval revalidates the stored canonical bundle; the browser cannot replace its rules. Idempotent receipts retain the latest 64 applies per session. History retains 60 snapshots; audit 100 events; chart 120 samples; proposal cache 16 entries. Each snapshot stores control settings, rules, and administrative link parameters, not telemetry or API keys.

Strict validation rejects unknown fields, bool-as-number, NaN/infinity, unknown hosts/actions/apps/links, protocol-port mismatches, unconstrained global drop, and management-host SSH blocks. Overlapping selectors are compared across source/destination/application/protocol/port, including wildcards. Contradictory block/nonblock, differing aggregate caps and incompatible explicit routes are rejected rather than silently shadowed. Blocks are intentional isolation, so host-to-host reachability is not globally guaranteed for blocked application traffic.

## Server and session design
A single process hosts a standard-library threaded HTTP server with at most 64 worker slots. A registry of at most 64 visitor twins uses opaque HttpOnly SameSite=Strict cookies. Idle TTL is 30 minutes. A background clock snapshots the registry before taking individual twin locks. Slow Google requests happen outside model locks. Request bodies cap at 16 KB, intents at 1000 characters, active rules at 64. Mutations require CSRF token and accepted same-origin headers. Security headers block inline scripts, framing and cross-origin scripts. Visitor state is disposable, not durable private storage.

Google requests reserve quota before I/O, use a server-side key header, require free-tier confirmation, and never fall back to a paid model. Only selected intent text and the fixed policy schema are sent to Google, not account data or session history. Response JSON is strictly revalidated. A failed call reports an error, never silently invents an AI response.

## Deliberately omitted from the original proposal
Mininet, Ryu, Open vSwitch, LLDP discovery, ARP proxying, true OpenFlow compilation, meters/queues, packet capture, iperf/ping measurements, Prometheus/Grafana deployment, trained LSTM, ARIMA fitting, FRRouting/OSPF comparison and physical hardware. A visitor-scoped Prometheus text endpoint is available at /metrics, but it exports model estimates only. This adaptation follows the request to work independently without requiring a privileged local lab.

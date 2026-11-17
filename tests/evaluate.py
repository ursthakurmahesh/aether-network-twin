"""Run model-only comparisons. These are NOT packet, Mininet, OSPF or LSTM benchmarks."""
import json,math,statistics,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core import Twin,pairs

def trial(seed,healing,proactive):
    t=Twin();t.autoheal=healing;t.proactive=proactive;t.surge=2
    for _ in range(15+seed):t.step()
    key=pairs(t.flows[0]['path'])[0];t.links[key]['up']=False
    result=[]
    for _ in range(30):t.step();result.append(t.metrics())
    return dict(mean_throughput=statistics.mean(r['throughput'] for r in result),mean_loss_pct=statistics.mean(r['loss'] for r in result),mean_rtt_estimate=statistics.mean(r['latency'] for r in result))

def main():
    result={'provenance':'Executed deterministic mathematical model, synthetic sinusoidal workload. Not real networking performance. No OSPF/LSTM claims.','steps_per_trial':30,'trials':10,'modes':{}}
    for mode,a,p in [('static_model',False,False),('reactive_model',True,False),('forecast_aware_model',True,True)]:
        rows=[trial(i,a,p) for i in range(10)];result['modes'][mode]={k:{'mean':round(statistics.mean(r[k] for r in rows),4),'stdev':round(statistics.stdev(r[k] for r in rows),4)} for k in rows[0]}
    # Walk-forward five-step forecasting on held-out model telemetry. Train/val/test are chronological.
    series=[.5+.3*math.sin(i/15)+.1*math.sin(i/4) for i in range(300)]
    errors={'moving_average':[],'moving_average_trend':[]}
    for i in range(210,295):
        xs=series[i-8:i];actual=series[i+4];ma=statistics.mean(xs);trend=ma+5*(xs[-1]-xs[0])/7
        for k,pred in [('moving_average',ma),('moving_average_trend',trend)]:errors[k].append(pred-actual)
    result['forecast_evaluation']={'source':'synthetic analytical utilization series, not trained on real traffic','split':'first 150 train reference, next 60 validation reference, final 90 held-out test; fixed baselines require no fitting','lead_steps':5,'samples':85,'metrics':{k:{'MAE':round(statistics.mean(abs(x) for x in es),6),'RMSE':round(math.sqrt(statistics.mean(x*x for x in es)),6)} for k,es in errors.items()}}
    target=Path(__file__).resolve().parents[1]/'docs'/'model-evaluation.json';target.write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
if __name__=='__main__':main()

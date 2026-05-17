import json
from pathlib import Path

def main():
    with open("data/processed/hybrid_real_evaluation.json", "r", encoding="utf-8") as f:
        data = json.load(f)
        
    packages = data["packages"]
    
    def evaluate(ap, ab, block_suspicious=False):
        preds = []
        labels = []
        for pkg in packages:
            gnn = pkg["gnn_score"]
            rules_score = pkg["rules_score"]
            has_crit = pkg["rules_critical"]
            label = pkg["true_label"]
            labels.append(label)
            
            # 1. Critical
            if has_crit:
                preds.append(1)
                continue
                
            # 2. Auto-block
            if gnn >= ab:
                preds.append(1)
                continue
                
            # 3. Auto-pass
            if gnn <= ap:
                if rules_score >= 15.0:
                    preds.append(1)
                else:
                    preds.append(0)
                continue
                
            # 4. Uncertain
            if rules_score >= 15.0:
                preds.append(1)
            elif rules_score > 0 and block_suspicious:
                preds.append(1)
            else:
                preds.append(0)
                
        # Metrics
        tp = sum(1 for p, l in zip(preds, labels) if p == 1 and l == 1)
        fp = sum(1 for p, l in zip(preds, labels) if p == 1 and l == 0)
        fn = sum(1 for p, l in zip(preds, labels) if p == 0 and l == 1)
        prec = tp / max(tp + fp, 1)
        rec = tp / max(tp + fn, 1)
        f1 = 2 * prec * rec / max(prec + rec, 1e-9)
        return prec, rec, f1, fp, fn

    print("=== Not Blocking Suspicious ===")
    for ap in [0.25, 0.35, 0.45]:
        for ab in [0.75, 0.85, 0.90, 0.95]:
            p, r, f1, fp, fn = evaluate(ap, ab, block_suspicious=False)
            if p >= 0.97:
                print(f"AP={ap:.2f} AB={ab:.2f} -> P={p:.4f} R={r:.4f} F1={f1:.4f} FP={fp} FN={fn}")

if __name__ == "__main__":
    main()

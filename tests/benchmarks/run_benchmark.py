import sys
import os
import json
from datetime import datetime
from unittest.mock import mock_open, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from tools.log_analysis_tool import LogAnalysisTool
from tests.benchmarks.ground_truth import BENCHMARK_SCENARIOS

def run_benchmark():
    tool = LogAnalysisTool()
    results = []
    
    total = len(BENCHMARK_SCENARIOS)
    correct_detections = 0
    correct_severity   = 0
    false_positives    = 0
    false_negatives    = 0

    print("\n" + "="*60)
    print("CYBERSECURITY DETECTION BENCHMARK")
    print(f"Running {total} scenarios...")
    print("="*60)

    for scenario in BENCHMARK_SCENARIOS:
        log_content = "\n".join(scenario["injected_logs"])

        def fake_open(path, mode="r", errors=None):
            return mock_open(read_data=log_content)()

        with patch("builtins.open", side_effect=fake_open):
            result = tool._run("mock_auth.log")

        detected_types = {d["threat_type"] for d in result["detections"]}
        expected_types = set(scenario["expected_detections"])

        # Detection accuracy
        tp = detected_types & expected_types          # true positives
        fp = detected_types - expected_types          # false positives
        fn = expected_types - detected_types          # false negatives

        detection_correct = (tp == expected_types and len(fp) == 0)
        
        # Severity accuracy
        if result["detections"]:
            sev_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            actual_sev = max(
                result["detections"],
                key=lambda x: sev_map.get(x["severity"], 0)
            )["severity"]
        else:
            actual_sev = "LOW"
        
        severity_correct = (actual_sev == scenario["expected_severity"])

        if detection_correct:
            correct_detections += 1
        if severity_correct:
            correct_severity += 1
        false_positives += len(fp)
        false_negatives += len(fn)

        status = "✅ PASS" if detection_correct and severity_correct else "❌ FAIL"
        print(f"\n{status} [{scenario['scenario_id']}] {scenario['name']}")
        print(f"  Expected:  {expected_types or '{clean}'} | {scenario['expected_severity']}")
        print(f"  Detected:  {detected_types or '{clean}'} | {actual_sev}")
        if fp: print(f"  False +ve: {fp}")
        if fn: print(f"  False -ve: {fn}")

        results.append({
            "scenario_id":        scenario["scenario_id"],
            "name":               scenario["name"],
            "detection_correct":  detection_correct,
            "severity_correct":   severity_correct,
            "true_positives":     list(tp),
            "false_positives":    list(fp),
            "false_negatives":    list(fn),
            "expected_severity":  scenario["expected_severity"],
            "actual_severity":    actual_sev,
        })

    # ── Summary ──────────────────────────────────────────────────────────
    detection_acc = round(correct_detections / total * 100, 1)
    severity_acc  = round(correct_severity   / total * 100, 1)
    overall_acc   = round((correct_detections + correct_severity) / (total * 2) * 100, 1)
    fp_rate       = round(false_positives / (false_positives + correct_detections + 0.001) * 100, 1)

    print("\n" + "="*60)
    print("BENCHMARK RESULTS")
    print("="*60)
    print(f"Detection Accuracy:  {detection_acc}%  ({correct_detections}/{total} scenarios)")
    print(f"Severity Accuracy:   {severity_acc}%  ({correct_severity}/{total} scenarios)")
    print(f"Overall Accuracy:    {overall_acc}%")
    print(f"False Positive Rate: {fp_rate}%")
    print(f"Total False +ve:     {false_positives}")
    print(f"Total False -ve:     {false_negatives}")
    print("="*60)

    # ── Save report ───────────────────────────────────────────────────────
    report = {
        "benchmark_run": datetime.now().isoformat(),
        "summary": {
            "total_scenarios":    total,
            "detection_accuracy": detection_acc,
            "severity_accuracy":  severity_acc,
            "overall_accuracy":   overall_acc,
            "false_positive_rate": fp_rate,
            "false_positives":    false_positives,
            "false_negatives":    false_negatives,
        },
        "scenarios": results,
    }

    os.makedirs("tests/benchmarks", exist_ok=True)
    with open("tests/benchmarks/benchmark_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved → tests/benchmarks/benchmark_report.json")
    
    return report

if __name__ == "__main__":
    run_benchmark()
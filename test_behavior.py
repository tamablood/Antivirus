
import os
import time
import shutil
import tempfile
from behavior_analyzer import BehaviorMonitor

def run_test():
    # 1. Setup temp dir
    test_dir = tempfile.mkdtemp(prefix="beh_test_")
    print(f"Testing in {test_dir}")
    
    try:
        monitor = BehaviorMonitor(test_dir)
        monitor.start()
        
        # 2. Test Creations
        print("--- Testing Creations ---")
        for i in range(6):
            with open(os.path.join(test_dir, f"file_{i}.txt"), "w") as f:
                f.write("content")
        
        # Poll
        current = monitor.snapshot()
        diffs = monitor.check_diff(current)
        print("Diffs detected:", len(diffs))
        for d in diffs:
            print("  ", d)
            
        alerts = monitor.analyze_patterns()
        print("Alerts:", len(alerts))
        for a in alerts:
            print(f"  [{a.level}] {a.message}")

        if any("Activité suspecte" in a.message for a in alerts):
            print("SUCCESS: Creation alert triggered.")
        else:
            print("FAILURE: Creation alert NOT triggered.")
            
        # 3. Test Deletions (Ransomware simulation)
        time.sleep(1)
        print("\n--- Testing Deletions ---")
        for i in range(6):
            try:
                os.remove(os.path.join(test_dir, f"file_{i}.txt"))
            except OSError:
                pass
                
        current = monitor.snapshot()
        diffs = monitor.check_diff(current)
        print("Diffs detected:", len(diffs))
        
        alerts = monitor.analyze_patterns()
        print("Alerts:", len(alerts))
        for a in alerts:
            print(f"  [{a.level}] {a.message}")
            
        if any("RANSOMWARE" in a.message for a in alerts):
            print("SUCCESS: Deletion alert triggered.")
        else:
            print("FAILURE: Deletion alert NOT triggered.")

    finally:
        monitor.stop()
        shutil.rmtree(test_dir)
        print("Cleanup done.")

if __name__ == "__main__":
    run_test()

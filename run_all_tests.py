#!/usr/bin/env python3
"""
Master Test Runner - Executes all DH and security tests
Run this to execute all test scripts in sequence
"""

import subprocess
import sys
from pathlib import Path

def run_test(script_name, description):
    """Run a test script and display results"""
    print("\n" + "=" * 80)
    print(f"  {description}")
    print("=" * 80)
    
    try:
        result = subprocess.run(
            [sys.executable, script_name],
            capture_output=False,
            text=True
        )
        if result.returncode == 0:
            print(f"\n✓ {description} - PASSED")
            return True
        else:
            print(f"\n✗ {description} - FAILED")
            return False
    except FileNotFoundError:
        print(f"\n✗ {description} - Script not found: {script_name}")
        return False
    except Exception as e:
        print(f"\n✗ {description} - Error: {e}")
        return False

def main():
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 20 + "SECURE CHAT - MASTER TEST SUITE" + " " * 26 + "║")
    print("╚" + "=" * 78 + "╝")
    
    tests = [
        ("test_dh_params.py", "DH Parameter Generation"),
        ("test_dh_exchange.py", "Complete DH Key Exchange"),
        ("test_key_derivation.py", "Session Key Derivation"),
        ("test_aes_with_dh.py", "AES Encryption with DH Key"),
        ("show_protocol_flow.py", "Protocol Flow Diagram"),
        ("test_tampering_detection.py", "Message Tampering Detection"),
        ("test_replay_prevention.py", "Replay Attack Prevention"),
    ]
    
    results = []
    
    for script, description in tests:
        passed = run_test(script, description)
        results.append((description, passed))
    
    # Summary
    print("\n\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 30 + "TEST SUMMARY" + " " * 36 + "║")
    print("╚" + "=" * 78 + "╝")
    print()
    
    total = len(results)
    passed = sum(1 for _, p in results if p)
    failed = total - passed
    
    print(f"Total Tests:  {total}")
    print(f"Passed:       {passed} ✓")
    print(f"Failed:       {failed} ✗")
    print()
    
    print("Detailed Results:")
    print("-" * 80)
    for desc, success in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status:10} {desc}")
    
    print("\n" + "=" * 80)
    
    if passed == total:
        print("✓ ALL TESTS PASSED!")
        print("✓ Ready for assignment submission!")
        return 0
    else:
        print("⚠ SOME TESTS FAILED")
        print("  Please check the failed tests above")
        return 1

if __name__ == "__main__":
    sys.exit(main())

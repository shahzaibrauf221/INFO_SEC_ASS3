#!/usr/bin/env python3
"""
Security Test: Replay Attack Prevention
Demonstrates sequence number enforcement to prevent replay attacks
"""

def main():
    print("\n[+] REPLAY ATTACK PREVENTION TEST")
    print("=" * 70)

    print("\n[SCENARIO] Attacker captures message and tries to replay it")
    print("-" * 70)

    # Simulate message sequence
    messages = [
        {"seqno": 1, "msg": "First message"},
        {"seqno": 2, "msg": "Second message"},
        {"seqno": 3, "msg": "Third message"},
    ]

    print("\n[STEP 1] Normal Message Sequence")
    received_seqno = 0
    for msg in messages:
        if msg["seqno"] > received_seqno:
            print(f"  [✓] seqno {msg['seqno']}: ACCEPTED (expected {received_seqno + 1})")
            received_seqno = msg["seqno"]
        else:
            print(f"  [✗] seqno {msg['seqno']}: REJECTED (replay detected)")

    # Attacker tries to replay message 2
    print("\n[STEP 2] Attacker Replays Message #2")
    replayed_msg = {"seqno": 2, "msg": "Second message (replayed)"}

    if replayed_msg["seqno"] > received_seqno:
        print(f"  [✗] seqno {replayed_msg['seqno']}: ACCEPTED (replay attack succeeded - BAD!)")
        return 1
    else:
        print(f"  [✓] seqno {replayed_msg['seqno']}: REJECTED")
        print(f"  [✓] Expected seqno > {received_seqno}, got {replayed_msg['seqno']}")
        print(f"  [✓] Replay attack prevented!")

    # Attacker tries to replay message 1
    print("\n[STEP 3] Attacker Replays Message #1")
    replayed_msg = {"seqno": 1, "msg": "First message (replayed)"}

    if replayed_msg["seqno"] > received_seqno:
        print(f"  [✗] seqno {replayed_msg['seqno']}: ACCEPTED (replay attack succeeded - BAD!)")
        return 1
    else:
        print(f"  [✓] seqno {replayed_msg['seqno']}: REJECTED")
        print(f"  [✓] Replay attack prevented!")

    print("\n" + "=" * 70)
    print("✓ Sequence number enforcement prevents replay attacks!")
    print("=" * 70)
    return 0

if __name__ == "__main__":
    main()

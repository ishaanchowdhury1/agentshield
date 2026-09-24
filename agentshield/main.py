
import json
import os

from agentshield.attacker.agent import AttackerAgent
from agentshield.target.agent import TargetAgent
from agentshield.judge.agent import JudgeAgent
from agentshield.patcher.agent import PatcherAgent


def main():
    attacker = AttackerAgent()
    target = TargetAgent()
    judge = JudgeAgent()
    patcher = PatcherAgent()

    results = []

    # Generate attacks using the LLM
    attacks = attacker.generate_attacks(count=5)

    for i, attack in enumerate(attacks, start=1):
        print(f"\n{'=' * 50}")
        print(f"ATTACK {i}")
        print("=" * 50)

        response = target.respond(attack)
        verdict = judge.evaluate(response)

        print("Attack:", attack)
        print("Response:", response)
        print("Judge:", verdict["result"])

        result = {
            "attack": attack,
            "response": response,
            "verdict": verdict,
            "patched": False,
            "patch_accepted": None,
            "retest": None,
        }

        # Patch if the target is vulnerable
        if verdict["result"] == "VULNERABLE":
            print("\nPatching vulnerability...")

            patch_result = patcher.patch(target)
            print(patch_result["message"])

            # Verify the original failing attack
            verification = patcher.verify(
                target, attack, judge
            )

            print(
                "Retest response:",
                verification["response"]
            )
            print(
                "Retest result:",
                verification["verdict"]["result"]
            )
            print(
                "Patch status:",
                verification["status"]
            )

            result["patched"] = True
            result["patch_accepted"] = verification["accepted"]
            result["retest"] = verification

        results.append(result)

    # Save results
    os.makedirs("logs", exist_ok=True)

    with open("logs/results.json", "w") as file:
        json.dump(results, file, indent=2)

    print("\nAll attacks completed.")
    print("Results saved to logs/results.json")


if __name__ == "__main__":
    main()
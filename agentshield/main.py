import json

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

    for attack in attacker.generate_attacks():
        response = target.respond(attack)
        verdict = judge.evaluate(response)

        print("\nAttack:", attack)
        print("Response:", response)
        print("Judge:", verdict["result"])

        if verdict["result"] == "VULNERABLE":
            print("\nPatching vulnerability...")
            print(patcher.patch(target))

            # Verify the original attack again
            response = target.respond(attack)
            verdict = judge.evaluate(response)

            print("Retest response:", response)
            print("Retest result:", verdict["result"])

        results.append({
            "attack": attack,
            "response": response,
            **verdict,
        })

    with open("logs/results.json", "w") as file:
        json.dump(results, file, indent=2)

    print("\nResults saved to logs/results.json")


if __name__ == "__main__":
    main()

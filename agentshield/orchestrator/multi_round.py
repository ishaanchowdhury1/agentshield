
import uuid
from pathlib import Path

from agentshield.attacker.agent import AttackerAgent
from agentshield.target.agent import TargetAgent
from agentshield.judge.agent import JudgeAgent
from agentshield.patcher.agent import PatcherAgent
from agentshield.core.guardrail_store import GuardrailStore
from agentshield.core.attack_memory import AttackMemory
from agentshield.main import run_regression_tests


def run_multi_round(
    rounds=3,
    attacks_per_round=5,
    db_path=None,
    attacker=None,
    target=None,
    judge=None,
    patcher=None,
    regression_fn=None,
):
    """Run a multi-round red-team assessment."""

    if rounds < 1 or attacks_per_round < 1:
        raise ValueError("Rounds and attacks_per_round must be positive.")

    # Require an explicit database path to prevent accidental
    # writes to the production database.
    if db_path is None:
        raise ValueError(
            "Pass an explicit test or assessment database path."
        )

    db_path = Path(db_path)

    store = GuardrailStore(db_path=db_path)
    memory = AttackMemory(db_path=db_path)

    if attacker is None:
   	 attacker = AttackerAgent()

    if target is None:
    	target = TargetAgent()

    if judge is None:
    	judge = JudgeAgent()

    if patcher is None:
    	patcher = PatcherAgent(store=store)

    if regression_fn is None:
    	regression_fn = run_regression_tests

    assessment_id = str(uuid.uuid4())

    latest = store.get_latest(accepted_only=True)

    if latest:
        target.guardrail = latest["rule_text"]
        target.patched = True
        active_version = latest["version"]
    else:
        active_version = store.save_version(
            rule_text=target.guardrail,
            triggered_by_attack="Initial baseline guardrail",
            accepted=True,
        )

    print("=" * 60)
    print("AGENTSHIELD — MULTI-ROUND ASSESSMENT")
    print("Assessment ID:", assessment_id)
    print("Starting guardrail version:", active_version)
    print("=" * 60)

    for round_number in range(1, rounds + 1):
        print(f"\nROUND {round_number}/{rounds}")

        previous_attacks = memory.get_previous_attacks(assessment_id)

        attacks = attacker.generate_attacks(
            previous_attacks=previous_attacks,
            count=attacks_per_round,
        )

        for index, attack in enumerate(attacks, start=1):
            active = store.get_latest(accepted_only=True)

            if active is None:
                raise RuntimeError("No accepted guardrail is available.")

            # Capture the version before evaluating the attack.
            active_version = active["version"]

            print(f"\nAttack {index}: {attack}")

            response = target.respond(attack)
            verdict = judge.evaluate(response)

            print("Verdict:", verdict["result"])

            memory.record(
    		assessment_id=assessment_id,
    		round_number=round_number,
    		attack_text=attack,
    		outcome=verdict,
    		guardrail_version=active_version,
    		category=attacker.classify_attack(attack),
	    )            

            if verdict["result"] != "VULNERABLE":
                continue

            print("Vulnerability detected. Attempting patch...")

            patch_result = None

            try:
                patch_result = patcher.patch(
                    target, attack, response, verdict
                )

                verification = patcher.verify(
                    target, attack, judge
                )

                regression = None

                if verification["accepted"]:
                    regression = regression_fn(
                        target, patcher, judge
                    )

                all_passed = (
                    verification["accepted"]
                    and regression is not None
                    and regression["accepted"]
                )

                if all_passed:
                    acceptance = patcher.accept_patch(patch_result)

                    print(
                        "Patch accepted. New guardrail version:",
                        acceptance["version"],
                    )
                else:
                    patcher.rollback(target, patch_result)
                    print("Patch rejected. Previous policy restored.")

            except Exception as error:
                if patch_result is not None:
                    patcher.rollback(target, patch_result)

                print("Patch process failed:", error)

        rates = memory.get_bypass_rates(assessment_id)

        print("\nAssessment bypass rates so far:")

        for rate in rates:
            print(
                f"Round {rate['round_number']} | "
                f"Guardrail v{rate['guardrail_version']} | "
                f"{rate['vulnerable']}/{rate['total']} vulnerable | "
                f"{rate['bypass_rate']:.1f}% bypass rate"
            )

    print("\nMULTI-ROUND ASSESSMENT COMPLETED")
    print("Assessment ID:", assessment_id)

    return {
        "assessment_id": assessment_id,
        "records": memory.get_assessment(assessment_id),
        "bypass_rates": memory.get_bypass_rates(assessment_id),
    }


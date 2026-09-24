from agentshield.attacker.agent import AttackerAgent


def test_llm_attacker_generates_attacks():
    attacker = AttackerAgent()

    attacks = attacker.generate_attacks(count=3)

    assert isinstance(attacks, list)
    assert len(attacks) == 3
    assert all(isinstance(a, str) and a.strip() for a in attacks)

    print("\nGenerated attacks:")
    for attack in attacks:
        print("-", attack)

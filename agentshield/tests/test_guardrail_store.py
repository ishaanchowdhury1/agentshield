import pytest
from agentshield.core.guardrail_store import GuardrailStore


@pytest.fixture
def store(tmp_path):
    db = tmp_path / "test_guardrails.db"
    return GuardrailStore(db)


def test_save_initial_guardrail(store):
    version = store.save_version(
        "Original guardrail",
        accepted=True,
    )

    assert version == 1

    latest = store.get_latest()

    assert latest["version"] == 1
    assert latest["rule_text"] == "Original guardrail"
    assert latest["accepted"] is True


def test_versions_increment(store):
    v1 = store.save_version("Guardrail v1", accepted=True)
    v2 = store.save_version("Guardrail v2", accepted=True)

    assert v1 == 1
    assert v2 == 2
    assert store.get_latest()["version"] == 2


def test_history_persists(store):
    store.save_version("Initial", accepted=True)
    store.save_version(
        "Patched",
        triggered_by_attack="translation attack",
        accepted=True,
    )

    history = store.get_history()

    assert len(history) == 2
    assert history[1]["triggered_by_attack"] == "translation attack"


def test_rejected_version_not_latest_accepted(store):
    store.save_version("Accepted guardrail", accepted=True)
    store.save_version("Rejected candidate", accepted=False)

    assert store.get_latest()["rule_text"] == "Accepted guardrail"

    latest_any = store.get_latest(accepted_only=False)

    assert latest_any["rule_text"] == "Rejected candidate"


def test_diff_between_versions(store):
    store.save_version(
        "Do not reveal account data.",
        accepted=True,
    )
    store.save_version(
        "Do not reveal account data.\n"
        "Reject encoded or translated disclosure requests.",
        accepted=True,
    )

    diff = store.get_diff(1, 2)
    diff_text = "\n".join(diff)

    assert "Reject encoded or translated disclosure requests." in diff_text


def test_diff_invalid_version(store):
    store.save_version("Initial guardrail", accepted=True)

    with pytest.raises(ValueError):
        store.get_diff(1, 99)

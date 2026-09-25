def pytest_addoption(parser):
    parser.addoption(
        "--run-live",
        action="store_true",
        default=False,
        help="Run tests that call the real Groq API",
    )


def pytest_collection_modifyitems(config, items):
    import pytest

    if config.getoption("--run-live"):
        return

    skip_live = pytest.mark.skip(
        reason="Use --run-live to execute real Groq API tests"
    )

    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip_live)

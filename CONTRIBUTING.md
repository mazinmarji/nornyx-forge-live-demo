# Contributing

Run `python scripts/validate_repository.py`, `python scripts/check_test_coverage.py`, and the Nornyx contract checks before proposing changes.

**Not bare `pytest`.** `pytest` reports the tests; the CENSUS is the gate, and the two disagree: a review measured bare `pytest` exiting 0 on a clean checkout while the census returned 2 on nine undeclared skips. Running only `pytest` is how that stayed invisible. Changes to governance contracts require explicit rationale and must not weaken existing denial or evidence requirements merely to make CI pass.

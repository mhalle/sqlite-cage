"""Run the property-based fuzzer as a normal test with a small budget."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fuzz_cage import fuzz


def test_fuzz_invariants(db):
    seed, n_policies, violations = fuzz(db, n=600, seed=1)
    assert not violations, "\n".join(
        f"{m} | policy={p} | query={q!r} (seed {s})"
        for m, p, q, s in violations)

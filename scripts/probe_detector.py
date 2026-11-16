"""Print what the PII detector finds in sample text.

Dev aid: ``python scripts/probe_detector.py``.
"""

from __future__ import annotations

import time

from sentinel_vault.privacy.detector import PiiDetector, build_presidio_analyzer

SAMPLES = [
    "Patient John Smith (DOB 1984-07-19, MRN: 00A-7781-22) called from (415) 555-0134.",
    "SSN 123-45-6789, email j.marlowe@example-clinic.org, member id XKZ-99812",
    "Spaced SSN 1 2 3 - 4 5 - 6 7 8 9 and zero\u200bwidth 123\u200b-45-\u200b6789",
    "Homoglyph name J\u043ehn Sm\u0456th lives at 42 Elm Street, Springfield",
    "Jordan called about the Paris trip with Dr. Priya Raman on 03/14/2025",
    "Blood pressure 120/80, dose 500 mg twice daily, follow up in 2 weeks",
    "NPI 1234567893 for Dr. Alan Grant",
]


def main() -> None:
    t = time.time()
    d = PiiDetector(build_presidio_analyzer(), 0.35)
    print(f"load {time.time() - t:.1f}s")
    for s in SAMPLES:
        print(repr(s))
        for sp in d.detect_sync(s):
            print(f"    {sp.entity:<16} {sp.score:.2f} {s[sp.start:sp.end]!r}")


if __name__ == "__main__":
    main()

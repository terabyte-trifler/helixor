"""
tests/diagnosis/test_detector_finding_types.py — wire shape pin tests.

Pin every invariant the Day-36 kernel relies on for byte-identical output.
A regression here is a breaking on-chain change once Day 38 wires the
manifest hash into the scoring_code_hash.
"""

from __future__ import annotations

import math

import pytest

from diagnosis.detectors.types import DiagnosisFinding, EvidenceSpan


def _span(slot: int = 100, sig: str = "sig" + "0" * 61, ix: int = 0) -> EvidenceSpan:
    return EvidenceSpan(slot=slot, tx_sig=sig, ix_index=ix)


class TestEvidenceSpan:
    def test_construct_ok(self):
        s = _span()
        assert s.slot == 100 and s.ix_index == 0

    @pytest.mark.parametrize("bad_slot", [-1, "100", True])
    def test_bad_slot(self, bad_slot):
        with pytest.raises((TypeError, ValueError)):
            EvidenceSpan(slot=bad_slot, tx_sig="sig", ix_index=0)

    def test_empty_sig_rejected(self):
        with pytest.raises(ValueError):
            EvidenceSpan(slot=1, tx_sig="", ix_index=0)

    @pytest.mark.parametrize("bad_ix", [-1, "0", True])
    def test_bad_ix(self, bad_ix):
        with pytest.raises((TypeError, ValueError)):
            EvidenceSpan(slot=1, tx_sig="sig", ix_index=bad_ix)

    def test_orderable(self):
        a = EvidenceSpan(slot=1, tx_sig="a", ix_index=0)
        b = EvidenceSpan(slot=2, tx_sig="a", ix_index=0)
        c = EvidenceSpan(slot=1, tx_sig="b", ix_index=0)
        assert a < b
        assert a < c


class TestDiagnosisFinding:
    def _ok(self, **overrides):
        kw = dict(
            label_bit=35,
            confidence=0.7,
            evidence_spans=(_span(),),
            remediation_codes=0,
            detector_id="t@1",
        )
        kw.update(overrides)
        return DiagnosisFinding(**kw)

    def test_construct_ok(self):
        f = self._ok()
        assert f.label_value == (1 << 35)

    def test_label_bit_out_of_range(self):
        with pytest.raises(ValueError):
            self._ok(label_bit=64)
        with pytest.raises(ValueError):
            self._ok(label_bit=-1)

    @pytest.mark.parametrize("bad", [-0.01, 1.01, math.nan, math.inf])
    def test_confidence_invariants(self, bad):
        with pytest.raises(ValueError):
            self._ok(confidence=bad)

    def test_spans_canonicalised(self):
        s1 = EvidenceSpan(slot=2, tx_sig="z", ix_index=0)
        s2 = EvidenceSpan(slot=1, tx_sig="a", ix_index=0)
        f = self._ok(evidence_spans=(s1, s2))
        # __post_init__ sorts into canonical (slot, sig, ix_index) order.
        assert f.evidence_spans[0] == s2
        assert f.evidence_spans[1] == s1

    def test_remediation_codes_u32(self):
        with pytest.raises(ValueError):
            self._ok(remediation_codes=1 << 32)

    def test_detector_id_must_be_nonempty(self):
        with pytest.raises(ValueError):
            self._ok(detector_id="")

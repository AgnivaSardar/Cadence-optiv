"""Unit tests for PII recognizers — each recognizer tested individually."""

from __future__ import annotations

import pytest

from tprm.pii.recognizers import (
    APIKeyRecognizer,
    BankAccountRecognizer,
    ContractNumberRecognizer,
    CreditCardRecognizer,
    CredentialURLRecognizer,
    EmployeeIDRecognizer,
    IBANRecognizer,
    InternalHostnameRecognizer,
    MacAddressRecognizer,
    PEMPrivateKeyRecognizer,
    _iban_valid,
    _luhn_valid,
)


class TestLuhn:
    def test_valid_visa(self) -> None:
        assert _luhn_valid("4111111111111111")

    def test_valid_mastercard(self) -> None:
        assert _luhn_valid("5500005555555559")

    def test_invalid_card(self) -> None:
        assert not _luhn_valid("1234567890123456")

    def test_too_short(self) -> None:
        assert not _luhn_valid("1234")


class TestIBANValidation:
    def test_valid_gb_iban(self) -> None:
        assert _iban_valid("GB29 NWBK 6016 1331 9268 19")

    def test_invalid_iban(self) -> None:
        assert not _iban_valid("GB00 NWBK 0000 0000 0000 00")

    def test_too_short(self) -> None:
        assert not _iban_valid("GB29")


class TestIBANRecognizer:
    def _analyze(self, text: str) -> list[dict]:  # type: ignore[type-arg]
        rec = IBANRecognizer()
        results = rec.analyze(text, entities=["IBAN_CODE"])
        return [{"type": r.entity_type, "score": r.score} for r in results]

    def test_detects_valid_iban(self) -> None:
        results = self._analyze("Please pay to IBAN: GB29 NWBK 6016 1331 9268 19")
        iban_results = [r for r in results if r["type"] == "IBAN_CODE"]
        assert len(iban_results) > 0

    def test_does_not_detect_invalid_iban(self) -> None:
        # Invalid checksum — should fail validate_result
        results = self._analyze("IBAN: XX00 FAKE 0000 0000 0000 00")
        iban_results = [r for r in results if r["type"] == "IBAN_CODE"]
        # May still match pattern but score should be 0 after validation failure
        for r in iban_results:
            assert r["score"] == 0 or len(iban_results) == 0


class TestCreditCardRecognizer:
    def _analyze(self, text: str) -> list[dict]:  # type: ignore[type-arg]
        rec = CreditCardRecognizer()
        return rec.analyze(text, entities=["CREDIT_CARD"])

    def test_detects_valid_card(self) -> None:
        results = self._analyze("Card number: 4111-1111-1111-1111")
        assert len(results) > 0

    def test_invalid_card_not_detected(self) -> None:
        results = self._analyze("Number: 1234-5678-9012-3456")
        # Should not detect (fails Luhn) or score should be 0
        for r in results:
            assert r.score == 0 or len(results) == 0


class TestAPIKeyRecognizer:
    def _analyze(self, text: str) -> list[dict]:  # type: ignore[type-arg]
        rec = APIKeyRecognizer()
        return rec.analyze(text, entities=["API_KEY"])

    def test_detects_aws_key(self) -> None:
        results = self._analyze("AWS key: AKIAIOSFODNN7EXAMPLE and more")
        assert any(r.entity_type == "API_KEY" for r in results)

    def test_detects_github_token(self) -> None:
        results = self._analyze("Token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890")
        assert any(r.entity_type == "API_KEY" for r in results)

    def test_low_entropy_string_not_detected(self) -> None:
        # "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" — low entropy generic secret
        results = self._analyze("Secret: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        # Generic pattern may match but validate_result should reject low entropy
        for r in results:
            assert r.score == 0 or len(results) == 0


class TestMacAddressRecognizer:
    def _analyze(self, text: str) -> list[dict]:  # type: ignore[type-arg]
        rec = MacAddressRecognizer()
        return rec.analyze(text, entities=["MAC_ADDRESS"])

    def test_detects_colon_mac(self) -> None:
        results = self._analyze("MAC: 00:1A:2B:3C:4D:5E")
        assert len(results) > 0

    def test_detects_hyphen_mac(self) -> None:
        results = self._analyze("Interface: 00-1A-2B-3C-4D-5E")
        assert len(results) > 0


class TestPEMRecognizer:
    def _analyze(self, text: str) -> list[dict]:  # type: ignore[type-arg]
        rec = PEMPrivateKeyRecognizer()
        return rec.analyze(text, entities=["PEM_PRIVATE_KEY"])

    def test_detects_rsa_header(self) -> None:
        results = self._analyze("Key file:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAA...")
        assert len(results) > 0

    def test_detects_generic_private_key(self) -> None:
        results = self._analyze("-----BEGIN PRIVATE KEY-----")
        assert len(results) > 0

    def test_public_key_not_detected(self) -> None:
        results = self._analyze("-----BEGIN PUBLIC KEY-----")
        assert len(results) == 0


class TestInternalHostnameRecognizer:
    def _analyze(self, text: str, org_domains: list[str] | None = None) -> list[dict]:  # type: ignore[type-arg]
        rec = InternalHostnameRecognizer(org_domains=org_domains)
        return rec.analyze(text, entities=["INTERNAL_HOSTNAME"])

    def test_detects_internal_hostname(self) -> None:
        results = self._analyze("Server: db-primary.corp.acme.internal")
        assert len(results) > 0

    def test_detects_org_domain(self) -> None:
        results = self._analyze(
            "Server: api.acme.internal",
            org_domains=["acme.internal"],
        )
        assert len(results) > 0


class TestCredentialURLRecognizer:
    def _analyze(self, text: str) -> list[dict]:  # type: ignore[type-arg]
        rec = CredentialURLRecognizer()
        return rec.analyze(text, entities=["CREDENTIAL_URL"])

    def test_detects_url_with_credentials(self) -> None:
        results = self._analyze("DB: postgresql://admin:secret123@db.internal:5432/prod")
        assert len(results) > 0

    def test_plain_url_not_detected(self) -> None:
        results = self._analyze("Endpoint: https://api.example.com/v1/data")
        assert len(results) == 0


class TestOverlapResolution:
    def test_longer_span_wins(self) -> None:
        from tprm.common.models import Block, PIIEntity
        from tprm.pii.detector import _resolve_overlaps

        entities = [
            PIIEntity(block_id="b1", start=0, end=20, entity_type="EMAIL_ADDRESS", text="x" * 20, score=0.7, recognizer="r1"),
            PIIEntity(block_id="b1", start=0, end=10, entity_type="PHONE_NUMBER", text="x" * 10, score=0.9, recognizer="r2"),
        ]
        resolved = _resolve_overlaps(entities)
        assert len(resolved) == 1
        assert resolved[0].entity_type == "EMAIL_ADDRESS"  # longer span wins

    def test_non_overlapping_kept(self) -> None:
        from tprm.common.models import PIIEntity
        from tprm.pii.detector import _resolve_overlaps

        entities = [
            PIIEntity(block_id="b1", start=0, end=10, entity_type="EMAIL_ADDRESS", text="x" * 10, score=0.7, recognizer="r1"),
            PIIEntity(block_id="b1", start=20, end=30, entity_type="PHONE_NUMBER", text="x" * 10, score=0.7, recognizer="r2"),
        ]
        resolved = _resolve_overlaps(entities)
        assert len(resolved) == 2


class TestDetectorFiltering:
    def test_date_like_phone_number_false_positive_is_ignored(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from tprm.common.models import Block
        from tprm.pii import detector

        class FakeResult:
            def __init__(self) -> None:
                self.entity_type = "PHONE_NUMBER"
                self.start = 9
                self.end = 19
                self.score = 0.99
                self.recognition_metadata = {"recognizer_name": "fake-phone"}

        class FakeAnalyzer:
            def analyze(self, **_: object) -> list[FakeResult]:
                return [FakeResult()]

        monkeypatch.setattr(detector, "_get_analyzer", lambda **_: FakeAnalyzer())

        entities = detector.detect([Block(doc_id="d1", page=1, text="Due date 2024/01/31")])

        assert entities == []

    def test_month_year_date_range_false_positive_is_ignored(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from tprm.common.models import Block
        from tprm.pii import detector

        class FakeResult:
            def __init__(self) -> None:
                self.entity_type = "PHONE_NUMBER"
                self.start = 55
                self.end = 72
                self.score = 0.99
                self.recognition_metadata = {"recognizer_name": "fake-phone"}

        class FakeAnalyzer:
            def analyze(self, **_: object) -> list[FakeResult]:
                return [FakeResult()]

        monkeypatch.setattr(detector, "_get_analyzer", lambda **_: FakeAnalyzer())

        text = "Backend & Cloud Deployment Intern - VitaData Solutions 01/2026 - 07/2026"
        entities = detector.detect([Block(doc_id="d1", page=1, text=text)])

        assert entities == []

    def test_fallback_detects_contact_table_email_and_phone(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from tprm.common.models import Block
        from tprm.pii import detector

        class EmptyAnalyzer:
            def analyze(self, **_: object) -> list[object]:
                return []

        monkeypatch.setattr(detector, "_get_analyzer", lambda **_: EmptyAnalyzer())

        text = "Contact Miriam A. Tachebe m.tachebe@cadencefg.com, +1 (212) 555-0147"
        entities = detector.detect([Block(doc_id="d1", page=1, text=text)])
        entity_types = {entity.entity_type for entity in entities}

        assert "EMAIL_ADDRESS" in entity_types
        assert "PHONE_NUMBER" in entity_types

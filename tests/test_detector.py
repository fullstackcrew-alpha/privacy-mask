"""Tests for the sensitive information detector."""

import pytest
from mask_engine.ocr import OcrResult
from mask_engine.detector import detect_sensitive, _group_into_lines, Detection
from mask_engine.config import DetectionRule


def _make_rules():
    return [
        DetectionRule(name="PHONE_CN", pattern=r"1[3-9]\d[\s-]?\d{4}[\s-]?\d{4}", description="Phone", enabled=True),
        DetectionRule(name="EMAIL", pattern=r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", description="Email", enabled=True),
        DetectionRule(name="IP_ADDRESS", pattern=r"(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)", description="IP", enabled=True),
        DetectionRule(name="BIRTHDAY", pattern=r"(?:19|20)\d{2}[\s./-](?:0?[1-9]|1[0-2])[\s./-](?:0?[1-9]|[12]\d|3[01])", description="Birthday", enabled=True),
        DetectionRule(name="BANK_CARD", pattern=r"(?:62|4\d|5[1-5])\d{2}[\s.,-]?\d{4}[\s.,-]?\d{4}[\s.,-]?\d{4}(?:[\s.,-]?\d{1,3})?", description="Bank card", enabled=True),
        DetectionRule(name="PASSPORT_CN", pattern=r"(?<![A-Za-z0-9])[GEge]\d{8}(?![A-Za-z0-9])", description="Chinese passport number", enabled=True),
        DetectionRule(name="BIRTHDAY_EN", pattern=r"\d{1,2}\s*(?:JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)\s*(?:19|20)\d{2}", description="English date", enabled=True),
        DetectionRule(name="MRZ_LINE1", pattern=r"P[<«.O0][A-Z]{3}[A-Z<«.]{5,}", description="MRZ line 1", enabled=True),
        DetectionRule(name="MRZ_LINE2", pattern=r"[A-Z0-9][A-Z0-9<«]{29,}", description="MRZ line 2", enabled=True),
    ]


def _make_ocr(text: str, x: int, y: int, w: int = 80, h: int = 20, conf: float = 90) -> OcrResult:
    return OcrResult(text=text, confidence=conf, bbox=(x, y, w, h))


class TestGroupIntoLines:
    def test_single_line(self):
        results = [_make_ocr("hello", 0, 10), _make_ocr("world", 100, 12)]
        lines = _group_into_lines(results, y_threshold=10)
        assert len(lines) == 1
        assert len(lines[0]) == 2

    def test_two_lines(self):
        results = [
            _make_ocr("line1", 0, 10),
            _make_ocr("line2", 0, 50),
        ]
        lines = _group_into_lines(results, y_threshold=10)
        assert len(lines) == 2

    def test_empty(self):
        assert _group_into_lines([]) == []


class TestDetectSensitive:
    def test_phone_single_word(self):
        ocr = [_make_ocr("13812345678", 10, 10)]
        dets = detect_sensitive(ocr, _make_rules())
        assert len(dets) == 1
        assert dets[0].label == "PHONE_CN"

    def test_phone_multi_word(self):
        """Phone number split across multiple OCR words."""
        ocr = [
            _make_ocr("138", 10, 10, w=30),
            _make_ocr("1234", 50, 10, w=40),
            _make_ocr("5678", 100, 10, w=40),
        ]
        dets = detect_sensitive(ocr, _make_rules())
        assert len(dets) == 1
        assert dets[0].label == "PHONE_CN"
        # bbox should span all three words
        assert dets[0].bbox[0] == 10  # left of first word
        assert dets[0].bbox[0] + dets[0].bbox[2] == 140  # right of last word

    def test_email(self):
        ocr = [_make_ocr("user@example.com", 10, 10, w=160)]
        dets = detect_sensitive(ocr, _make_rules())
        assert len(dets) == 1
        assert dets[0].label == "EMAIL"

    def test_email_split_adjacent(self):
        """Email split by OCR into adjacent parts (small gap) should be detected."""
        ocr = [
            _make_ocr("user@example", 10, 10, w=120),
            _make_ocr(".com", 132, 10, w=40),  # gap=2px, within threshold
        ]
        dets = detect_sensitive(ocr, _make_rules())
        assert len(dets) == 1
        assert dets[0].label == "EMAIL"

    def test_email_split_wide_gap(self):
        """Email split with large gap won't be detected (space inserted)."""
        ocr = [
            _make_ocr("user@example", 10, 10, w=120),
            _make_ocr(".com", 200, 10, w=40),  # gap=70px, space inserted
        ]
        dets = detect_sensitive(ocr, _make_rules())
        assert len(dets) == 0

    def test_ip_address(self):
        ocr = [_make_ocr("192.168.1.100", 10, 10, w=120)]
        dets = detect_sensitive(ocr, _make_rules())
        assert len(dets) == 1
        assert dets[0].label == "IP_ADDRESS"

    def test_birthday(self):
        ocr = [_make_ocr("1990-01-15", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert len(dets) == 1
        assert dets[0].label == "BIRTHDAY"

    def test_no_sensitive_info(self):
        ocr = [_make_ocr("Hello", 10, 10), _make_ocr("World", 100, 10)]
        dets = detect_sensitive(ocr, _make_rules())
        assert len(dets) == 0

    def test_disabled_rule(self):
        rules = [DetectionRule(name="PHONE_CN", pattern=r"1[3-9]\d{9}", description="Phone", enabled=False)]
        ocr = [_make_ocr("13812345678", 10, 10)]
        dets = detect_sensitive(ocr, rules)
        assert len(dets) == 0

    def test_multiple_detections_same_line(self):
        ocr = [
            _make_ocr("13812345678", 10, 10, w=100),
            _make_ocr("user@test.com", 200, 10, w=120),
        ]
        dets = detect_sensitive(ocr, _make_rules())
        assert len(dets) == 2

    def test_multiple_lines(self):
        ocr = [
            _make_ocr("13812345678", 10, 10, w=100),
            _make_ocr("192.168.1.1", 10, 60, w=100),
        ]
        dets = detect_sensitive(ocr, _make_rules())
        assert len(dets) == 2


class TestDotNormalization:
    """Test dot-normalization second pass in detect_sensitive."""

    def test_dot_separated_phone(self):
        """Phone number with dots between digit groups (OCR noise) should be detected."""
        ocr = [_make_ocr("138.1234.5678", 10, 10, w=120)]
        rules = [DetectionRule(name="PHONE_CN", pattern=r"1[3-9]\d[\s-]?\d{4}[\s-]?\d{4}", description="Phone", enabled=True)]
        dets = detect_sensitive(ocr, rules)
        assert len(dets) == 1
        assert dets[0].label == "PHONE_CN"

    def test_dot_separated_bank_card(self):
        """Bank card number with dots should be detected via normalization."""
        ocr = [_make_ocr("6222.0200.1234.5678", 10, 10, w=200)]
        rules = [DetectionRule(
            name="BANK_CARD",
            pattern=r"(?:62|4\d|5[1-5])\d{2}[\s.,-]?\d{4}[\s.,-]?\d{4}[\s.,-]?\d{4}(?:[\s.,-]?\d{1,3})?",
            description="Bank card", enabled=True,
        )]
        dets = detect_sensitive(ocr, rules)
        assert len(dets) >= 1
        assert any(d.label == "BANK_CARD" for d in dets)

    def test_no_false_normalization_on_ip(self):
        """IP addresses should still be detected normally (dots are valid)."""
        ocr = [_make_ocr("192.168.1.100", 10, 10, w=120)]
        rules = [DetectionRule(
            name="IP_ADDRESS",
            pattern=r"(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)",
            description="IP", enabled=True,
        )]
        dets = detect_sensitive(ocr, rules)
        assert len(dets) == 1
        assert dets[0].label == "IP_ADDRESS"

    def test_no_dots_no_change(self):
        """Text without digit-dot-digit should not trigger normalization."""
        ocr = [_make_ocr("Hello World", 10, 10, w=100)]
        rules = _make_rules()
        dets = detect_sensitive(ocr, rules)
        assert len(dets) == 0


class TestPassportDetection:
    """Test passport-related detection rules."""

    def test_passport_cn_g_prefix(self):
        """Chinese passport number with G prefix."""
        ocr = [_make_ocr("G22212301", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "PASSPORT_CN" for d in dets)

    def test_passport_cn_e_prefix(self):
        """Chinese passport number with E prefix."""
        ocr = [_make_ocr("E12345678", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "PASSPORT_CN" for d in dets)

    def test_passport_cn_no_false_positive_in_longer_string(self):
        """Should not match passport number embedded in a longer alphanumeric string."""
        ocr = [_make_ocr("XG222123019", 10, 10, w=120)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "PASSPORT_CN" for d in dets)

    def test_birthday_en_no_space(self):
        """English date without spaces (e.g. 19DEC1996)."""
        ocr = [_make_ocr("19DEC1996", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "BIRTHDAY_EN" for d in dets)

    def test_birthday_en_with_spaces(self):
        """English date with spaces (e.g. 19 DEC 1996)."""
        ocr = [_make_ocr("19 DEC 1996", 10, 10, w=120)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "BIRTHDAY_EN" for d in dets)

    def test_birthday_en_lowercase(self):
        """English date with lowercase month should match (IGNORECASE)."""
        ocr = [_make_ocr("5jan2000", 10, 10, w=80)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "BIRTHDAY_EN" for d in dets)

    def test_mrz_line1(self):
        """MRZ line 1 with clean < separators."""
        ocr = [_make_ocr("P<CHNLI<<GUO<<<<<", 10, 10, w=300)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "MRZ_LINE1" for d in dets)

    def test_mrz_line1_ocr_dot_noise(self):
        """MRZ line 1 where OCR reads < as dots — should be caught by MRZ normalization."""
        ocr = [_make_ocr("POCHNL.I<<GUO<<<<<", 10, 10, w=300)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "MRZ_LINE1" for d in dets)

    def test_mrz_line2(self):
        """MRZ line 2 (44-char alphanumeric + filler sequence)."""
        ocr = [_make_ocr("G222123019CHN5612190M220221119200101<<<<<<44", 10, 10, w=500)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "MRZ_LINE2" for d in dets)

    def test_mrz_line2_short_text_no_match(self):
        """Short alphanumeric text should not match MRZ_LINE2."""
        ocr = [_make_ocr("ABC123DEF", 10, 10, w=80)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "MRZ_LINE2" for d in dets)

    def test_passport_full_page(self):
        """Simulate a full passport page with multiple sensitive fields."""
        ocr = [
            _make_ocr("G22212301", 100, 50, w=100),
            _make_ocr("19DEC1996", 100, 100, w=100),
            _make_ocr("22FEB2012", 100, 150, w=100),
            _make_ocr("P<CHNLI<<GUO<<<<<", 50, 300, w=400),
            _make_ocr("G222123019CHN5612190M220221119200101<<<<<<44", 50, 330, w=400),
        ]
        dets = detect_sensitive(ocr, _make_rules())
        all_labels = " ".join(d.label for d in dets)
        assert "PASSPORT_CN" in all_labels
        assert "BIRTHDAY_EN" in all_labels
        assert "MRZ_LINE1" in all_labels
        assert "MRZ_LINE2" in all_labels

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

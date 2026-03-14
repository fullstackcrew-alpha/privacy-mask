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
        DetectionRule(name="BIRTHDAY_EN", pattern=r"\d{1,2}\s*(?:JAN|FEB|FEV|MAR|APR|AVR|MAY|MAI|JUN|JUIN|JUL|JUIL|AUG|AOUT|SEP|SEPT|OCT|NOV|DEC)(?:/[A-Z]{2,5})?\s*\d{2,4}", description="EN/FR date", enabled=True),
        DetectionRule(name="MRZ_LINE1", pattern=r"P[<«.O0][A-Z]{3}[A-Z<«.]{5,}", description="MRZ line 1", enabled=True),
        DetectionRule(name="MRZ_LINE2", pattern=r"(?=[A-Z0-9<«]*[<«])[A-Z0-9<«]{30,}", description="MRZ line 2", enabled=True),
        DetectionRule(name="LICENSE_PLATE_CN", pattern=r"[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤川青藏琼宁][A-HJ-NP-Z][A-HJ-NP-Z0-9]{4,5}[A-HJ-NP-Z0-9挂学警港澳]?", description="License plate", enabled=True),
        DetectionRule(name="UNIFIED_CREDIT_CODE", pattern=r"[0-9]{2}[0-9]{6}[0-9A-HJ-NP-RTUW-Y]{10}", description="Credit code", enabled=True),
        DetectionRule(name="PHONE_CN_LANDLINE", pattern=r"0[1-9]\d{1,2}[\s-]\d{7,8}", description="Landline", enabled=True),
        DetectionRule(name="BIRTHDAY_CN", pattern=r"(?:19|20)\d{2}年(?:0?[1-9]|1[0-2])月(?:0?[1-9]|[12]\d|3[01])日", description="CN date", enabled=True),
        DetectionRule(name="URL_AUTH_TOKEN", pattern=r"https?://[^\s]*[?&](?:token|access_token|auth|session|jwt|key|secret|code|password)=[^\s&]{8,}", description="URL token", enabled=True),
        DetectionRule(name="QQ_NUMBER", pattern=r"(?:QQ|qq)[:\s：]*\d{5,12}", description="QQ", enabled=True),
        DetectionRule(name="WECHAT_ID", pattern=r"(?:微信|WeChat|wechat)[:\s：]*[a-zA-Z][a-zA-Z0-9_-]{5,19}", description="WeChat", enabled=True),
        DetectionRule(name="HKID", pattern=r"[A-Z]{1,2}\d{6}\(\d\)", description="HKID", enabled=True),
        DetectionRule(name="TWID", pattern=r"(?<![A-Za-z])[A-Z][12]\d{8}(?![A-Za-z0-9])", description="TWID", enabled=True),
        DetectionRule(name="IBAN", pattern=r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?:[\s]?[\dA-Z]{4}){2,7}(?:[\s]?[\dA-Z]{1,4})?(?![A-Za-z0-9])", description="IBAN", enabled=True),
        DetectionRule(name="PEM_PRIVATE_KEY", pattern=r"-----BEGIN[\s\w]*(?:PRIVATE KEY|CERTIFICATE)-----", description="PEM key", enabled=True),
        DetectionRule(name="SSH_KEY", pattern=r"ssh-(?:rsa|ed25519|dsa|ecdsa)\s+[A-Za-z0-9+/=]{20,}", description="SSH key", enabled=True),
        DetectionRule(name="MAC_ADDRESS", pattern=r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", description="MAC", enabled=True),
        DetectionRule(name="UUID", pattern=r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", description="UUID", enabled=True),
        DetectionRule(name="IPV6", pattern=r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}", description="IPv6", enabled=True),
        # P0 — Global high-value rules
        DetectionRule(name="US_SSN", pattern=r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)", description="US SSN", enabled=True),
        DetectionRule(name="CREDIT_CARD_AMEX", pattern=r"(?<!\d)3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}(?!\d)", description="Amex", enabled=True),
        DetectionRule(name="PHONE_INTL", pattern=r"\+\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{2,4}[\s.-]?\d{2,4}[\s.-]?\d{0,4}", description="Intl phone", enabled=True),
        DetectionRule(name="AWS_ACCESS_KEY", pattern=r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])", description="AWS key", enabled=True),
        DetectionRule(name="AWS_SECRET_KEY", pattern=r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|SecretAccessKey|secret_access_key|AWSSecretKey|aws_secret_key)[\s=:\"']+[A-Za-z0-9+/]{40}", description="AWS secret key", enabled=True),
        DetectionRule(name="GITHUB_TOKEN", pattern=r"(?<![A-Za-z0-9])(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}(?![A-Za-z0-9])", description="GitHub token", enabled=True),
        DetectionRule(name="SLACK_TOKEN", pattern=r"(?<![A-Za-z0-9])xox[bpsa]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9])", description="Slack token", enabled=True),
        DetectionRule(name="GOOGLE_API_KEY", pattern=r"(?<![A-Za-z0-9])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9])", description="Google API key", enabled=True),
        DetectionRule(name="STRIPE_KEY", pattern=r"(?<![A-Za-z0-9])(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}(?![A-Za-z0-9])", description="Stripe key", enabled=True),
        # P1 — Country IDs + finance + developer
        DetectionRule(name="UK_NINO", pattern=r"(?<![A-Za-z])[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D](?![A-Za-z0-9])", description="UK NINO", enabled=True),
        DetectionRule(name="CANADIAN_SIN", pattern=r"(?<!\d)\d{3}-\d{3}-\d{3}(?!\d)", description="Canadian SIN", enabled=True),
        DetectionRule(name="INDIAN_AADHAAR", pattern=r"(?<!\d)[2-9]\d{3}\s\d{4}\s\d{4}(?!\d)", description="Aadhaar", enabled=True),
        DetectionRule(name="INDIAN_PAN", pattern=r"(?<![A-Za-z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Za-z0-9])", description="Indian PAN", enabled=True),
        DetectionRule(name="KOREAN_RRN", pattern=r"(?<!\d)\d{6}-[1-4]\d{6}(?!\d)", description="Korean RRN", enabled=True),
        DetectionRule(name="SINGAPORE_NRIC", pattern=r"(?<![A-Za-z0-9])[STFGM]\d{7}[A-Z](?![A-Za-z0-9])", description="SG NRIC", enabled=True),
        DetectionRule(name="SWIFT_BIC", pattern=r"(?<![A-Za-z0-9])[A-Z]{4}(?:AD|AE|AF|AG|AI|AL|AM|AO|AR|AS|AT|AU|AW|AZ|BA|BB|BD|BE|BF|BG|BH|BI|BJ|BM|BN|BO|BR|BS|BT|BW|BY|BZ|CA|CD|CF|CG|CH|CI|CK|CL|CM|CN|CO|CR|CU|CV|CW|CY|CZ|DE|DJ|DK|DM|DO|DZ|EC|EE|EG|ER|ES|ET|FI|FJ|FK|FM|FO|FR|GA|GB|GD|GE|GH|GI|GL|GM|GN|GP|GQ|GR|GT|GU|GW|GY|HK|HN|HR|HT|HU|ID|IE|IL|IM|IN|IQ|IR|IS|IT|JE|JM|JO|JP|KE|KG|KH|KI|KN|KP|KR|KW|KY|KZ|LA|LB|LC|LI|LK|LR|LS|LT|LU|LV|LY|MA|MC|MD|ME|MG|MH|MK|ML|MM|MN|MO|MP|MQ|MR|MS|MT|MU|MV|MW|MX|MY|MZ|NA|NC|NE|NF|NG|NI|NL|NO|NP|NR|NU|NZ|OM|PA|PE|PF|PG|PH|PK|PL|PM|PN|PR|PS|PT|PW|PY|QA|RE|RO|RS|RU|RW|SA|SB|SC|SD|SE|SG|SH|SI|SK|SL|SM|SN|SO|SR|SS|ST|SV|SX|SY|SZ|TC|TD|TG|TH|TJ|TK|TL|TM|TN|TO|TR|TT|TV|TW|TZ|UA|UG|UM|US|UY|UZ|VA|VC|VE|VG|VI|VN|VU|WF|WS|XK|YE|YT|ZA|ZM|ZW)[A-Z0-9]{2}(?:[A-Z0-9]{3})?(?![A-Za-z0-9])", description="SWIFT/BIC", enabled=True),
        DetectionRule(name="CRYPTO_WALLET_ETH", pattern=r"(?<![A-Za-z0-9])0x[0-9a-fA-F]{40}(?![A-Za-z0-9])", description="ETH wallet", enabled=True),
        DetectionRule(name="PHONE_US", pattern=r"(?<!\d)\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)", description="US phone", enabled=True),
        DetectionRule(name="JWT_TOKEN", pattern=r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", description="JWT", enabled=True),
        DetectionRule(name="CONNECTION_STRING", pattern=r"(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqp|mssql)://[^\s]{10,}", description="DB conn string", enabled=True),
        # P2 — Supplementary
        DetectionRule(name="MALAYSIAN_IC", pattern=r"(?<!\d)\d{6}-\d{2}-\d{4}(?!\d)", description="Malaysian IC", enabled=True),
        DetectionRule(name="CRYPTO_WALLET_BTC", pattern=r"(?<![A-Za-z0-9])(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})(?![A-Za-z0-9])", description="BTC wallet", enabled=True),
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

    def test_birthday_en_2digit_year(self):
        """Date with 2-digit year (e.g. 23 APR 87)."""
        ocr = [_make_ocr("23 APR 87", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "BIRTHDAY_EN" for d in dets)

    def test_birthday_en_bilingual(self):
        """Bilingual date format (e.g. APR/AVR)."""
        ocr = [_make_ocr("23 APR/AVR 87", 10, 10, w=120)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "BIRTHDAY_EN" for d in dets)

    def test_birthday_en_french_month(self):
        """French month name (e.g. 27 AOUT 22)."""
        ocr = [_make_ocr("27 AOUT 22", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "BIRTHDAY_EN" for d in dets)

    def test_birthday_en_bilingual_long(self):
        """Bilingual date with longer French month (e.g. AUG/AOUT)."""
        ocr = [_make_ocr("27 AUG/AOUT 22", 10, 10, w=130)]
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
        assert any("MRZ_LINE2" in d.label for d in dets)

    def test_mrz_line2_short_text_no_match(self):
        """Short alphanumeric text should not match MRZ_LINE2."""
        ocr = [_make_ocr("ABC123DEF", 10, 10, w=80)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "MRZ_LINE2" for d in dets)

    def test_mrz_line2_long_text_no_chevron_no_match(self):
        """Long uppercase text without MRZ chevrons should not match."""
        for text in [
            "NPMJSCOMSETTINGSFULLSTACKCREWTOKEN",
            "GRANULARACCESSTOKENSPROVIDETHEMOST",
            "YOUMUSTSELECTATLEASTONEORGANIZATION",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ12345678",
        ]:
            ocr = [_make_ocr(text, 10, 10, w=400)]
            dets = detect_sensitive(ocr, _make_rules())
            assert not any(d.label == "MRZ_LINE2" for d in dets), f"'{text}' should not match MRZ_LINE2"

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


class TestLicensePlateCN:
    def test_standard_plate(self):
        ocr = [_make_ocr("京A12345", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "LICENSE_PLATE_CN" for d in dets)

    def test_new_energy_plate(self):
        """New energy vehicle plate with 6 alphanumeric chars."""
        ocr = [_make_ocr("粤BD12345", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "LICENSE_PLATE_CN" for d in dets)

    def test_special_suffix(self):
        """Plate with 挂/学/警 suffix."""
        ocr = [_make_ocr("沪A1234警", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "LICENSE_PLATE_CN" for d in dets)

    def test_no_match_plain_text(self):
        ocr = [_make_ocr("Hello World", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "LICENSE_PLATE_CN" for d in dets)

    def test_various_provinces(self):
        for province in ["川", "鲁", "闽", "藏"]:
            ocr = [_make_ocr(f"{province}A12345", 10, 10, w=100)]
            dets = detect_sensitive(ocr, _make_rules())
            assert any(d.label == "LICENSE_PLATE_CN" for d in dets), f"Failed for {province}"


class TestUnifiedCreditCode:
    def test_valid_code(self):
        ocr = [_make_ocr("91110108MA01ABCDEF", 10, 10, w=200)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "UNIFIED_CREDIT_CODE" for d in dets)

    def test_all_numeric(self):
        ocr = [_make_ocr("911101080123456789", 10, 10, w=200)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "UNIFIED_CREDIT_CODE" for d in dets)

    def test_short_string_no_match(self):
        ocr = [_make_ocr("91110108", 10, 10, w=80)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "UNIFIED_CREDIT_CODE" for d in dets)


class TestPhoneCNLandline:
    def test_beijing_landline(self):
        ocr = [_make_ocr("010-12345678", 10, 10, w=120)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "PHONE_CN_LANDLINE" for d in dets)

    def test_4digit_area_code(self):
        ocr = [_make_ocr("0755-1234567", 10, 10, w=120)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "PHONE_CN_LANDLINE" for d in dets)

    def test_space_separator(self):
        ocr = [_make_ocr("021 12345678", 10, 10, w=120)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "PHONE_CN_LANDLINE" for d in dets)

    def test_no_separator_no_match(self):
        """Without separator, should not match to avoid false positives."""
        ocr = [_make_ocr("01012345678", 10, 10, w=120)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "PHONE_CN_LANDLINE" for d in dets)


class TestBirthdayCN:
    def test_standard_date(self):
        ocr = [_make_ocr("1990年1月15日", 10, 10, w=120)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "BIRTHDAY_CN" for d in dets)

    def test_zero_padded(self):
        ocr = [_make_ocr("2000年01月05日", 10, 10, w=120)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "BIRTHDAY_CN" for d in dets)

    def test_invalid_month_no_match(self):
        ocr = [_make_ocr("1990年13月15日", 10, 10, w=120)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "BIRTHDAY_CN" for d in dets)

    def test_invalid_day_no_match(self):
        ocr = [_make_ocr("1990年12月32日", 10, 10, w=120)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "BIRTHDAY_CN" for d in dets)


class TestURLAuthToken:
    def test_token_param(self):
        ocr = [_make_ocr("https://api.example.com/data?token=abc123def456ghi7", 10, 10, w=400)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("URL_AUTH_TOKEN" in d.label for d in dets)

    def test_access_token(self):
        ocr = [_make_ocr("https://example.com/cb?access_token=eyJhbGciOiJIUzI1NiJ9", 10, 10, w=400)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "URL_AUTH_TOKEN" for d in dets)

    def test_short_value_no_match(self):
        """Token value < 8 chars should not match."""
        ocr = [_make_ocr("https://example.com?token=abc", 10, 10, w=300)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "URL_AUTH_TOKEN" for d in dets)

    def test_no_token_param_no_match(self):
        ocr = [_make_ocr("https://example.com?page=123456789", 10, 10, w=300)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "URL_AUTH_TOKEN" for d in dets)


class TestQQNumber:
    def test_qq_with_colon(self):
        ocr = [_make_ocr("QQ:12345678", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "QQ_NUMBER" for d in dets)

    def test_qq_lowercase(self):
        ocr = [_make_ocr("qq 987654321", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "QQ_NUMBER" for d in dets)

    def test_qq_chinese_colon(self):
        ocr = [_make_ocr("QQ：12345", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "QQ_NUMBER" for d in dets)

    def test_short_number_no_match(self):
        """QQ number < 5 digits should not match."""
        ocr = [_make_ocr("QQ:1234", 10, 10, w=80)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "QQ_NUMBER" for d in dets)


class TestWeChatID:
    def test_wechat_cn(self):
        ocr = [_make_ocr("微信:abc123def", 10, 10, w=120)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "WECHAT_ID" for d in dets)

    def test_wechat_en(self):
        ocr = [_make_ocr("WeChat: myWechat_01", 10, 10, w=150)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("WECHAT_ID" in d.label for d in dets)

    def test_digit_start_no_match(self):
        """WeChat ID must start with a letter."""
        ocr = [_make_ocr("微信:123456", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "WECHAT_ID" for d in dets)

    def test_too_short_no_match(self):
        """WeChat ID < 6 chars should not match."""
        ocr = [_make_ocr("微信:ab12", 10, 10, w=80)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "WECHAT_ID" for d in dets)


class TestHKID:
    def test_single_letter(self):
        ocr = [_make_ocr("A123456(7)", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "HKID" for d in dets)

    def test_double_letter(self):
        ocr = [_make_ocr("AB123456(0)", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "HKID" for d in dets)

    def test_no_check_digit_no_match(self):
        ocr = [_make_ocr("A1234567", 10, 10, w=80)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "HKID" for d in dets)


class TestTWID:
    def test_valid_twid(self):
        ocr = [_make_ocr("A123456789", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "TWID" for d in dets)

    def test_gender_2(self):
        ocr = [_make_ocr("B234567890", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "TWID" for d in dets)

    def test_embedded_no_match(self):
        """Should not match when embedded in longer alphanumeric string."""
        ocr = [_make_ocr("XA123456789Y", 10, 10, w=120)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "TWID" for d in dets)


class TestIBAN:
    def test_german_iban(self):
        ocr = [_make_ocr("DE89 3704 0044 0532 0130 00", 10, 10, w=250)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("IBAN" in d.label for d in dets)

    def test_uk_iban_no_spaces(self):
        ocr = [_make_ocr("GB29NWBK60161331926819", 10, 10, w=200)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("IBAN" in d.label for d in dets)

    def test_short_no_match(self):
        ocr = [_make_ocr("AB12", 10, 10, w=40)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "IBAN" for d in dets)

    def test_french_iban(self):
        ocr = [_make_ocr("FR76 3000 6000 0112 3456 7890 189", 10, 10, w=300)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("IBAN" in d.label for d in dets)

    def test_false_positive_english_text(self):
        """Normal English text with numbers should not match IBAN."""
        ocr = [_make_ocr("REQUIRED 1234", 10, 10, w=120)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "IBAN" for d in dets)

    def test_false_positive_organization(self):
        """Common uppercase words followed by numbers should not match."""
        ocr = [_make_ocr("ORGANIZATION 5678", 10, 10, w=160)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "IBAN" for d in dets)

    def test_false_positive_continue(self):
        """Short country-code-like prefix with few digits should not match."""
        ocr = [_make_ocr("CO12 NTINUE", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "IBAN" for d in dets)

    def test_too_short_code_no_match(self):
        """Two-letter code + 2 digits + only one 4-char group is too short for IBAN."""
        ocr = [_make_ocr("AB12 CDEF", 10, 10, w=80)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "IBAN" for d in dets)


class TestPEMPrivateKey:
    def test_rsa_private_key(self):
        ocr = [_make_ocr("-----BEGIN RSA PRIVATE KEY-----", 10, 10, w=300)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "PEM_PRIVATE_KEY" for d in dets)

    def test_certificate(self):
        ocr = [_make_ocr("-----BEGIN CERTIFICATE-----", 10, 10, w=250)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("PEM_PRIVATE_KEY" in d.label for d in dets)

    def test_generic_private_key(self):
        ocr = [_make_ocr("-----BEGIN PRIVATE KEY-----", 10, 10, w=250)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "PEM_PRIVATE_KEY" for d in dets)


class TestSSHKey:
    def test_ssh_rsa(self):
        ocr = [_make_ocr("ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQ", 10, 10, w=300)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "SSH_KEY" for d in dets)

    def test_ssh_ed25519(self):
        ocr = [_make_ocr("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA", 10, 10, w=300)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "SSH_KEY" for d in dets)

    def test_short_key_no_match(self):
        ocr = [_make_ocr("ssh-rsa AAAA", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "SSH_KEY" for d in dets)


class TestMACAddress:
    def test_colon_format(self):
        ocr = [_make_ocr("00:1A:2B:3C:4D:5E", 10, 10, w=150)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "MAC_ADDRESS" for d in dets)

    def test_dash_format(self):
        ocr = [_make_ocr("00-1A-2B-3C-4D-5E", 10, 10, w=150)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "MAC_ADDRESS" for d in dets)

    def test_lowercase(self):
        ocr = [_make_ocr("aa:bb:cc:dd:ee:ff", 10, 10, w=150)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "MAC_ADDRESS" for d in dets)

    def test_too_short_no_match(self):
        ocr = [_make_ocr("00:1A:2B", 10, 10, w=80)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "MAC_ADDRESS" for d in dets)


class TestUUID:
    def test_valid_uuid(self):
        ocr = [_make_ocr("550e8400-e29b-41d4-a716-446655440000", 10, 10, w=300)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "UUID" for d in dets)

    def test_uppercase_uuid(self):
        ocr = [_make_ocr("550E8400-E29B-41D4-A716-446655440000", 10, 10, w=300)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "UUID" for d in dets)

    def test_missing_section_no_match(self):
        ocr = [_make_ocr("550e8400-e29b-41d4-a716", 10, 10, w=200)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "UUID" for d in dets)


class TestIPv6:
    def test_full_ipv6(self):
        ocr = [_make_ocr("2001:0db8:85a3:0000:0000:8a2e:0370:7334", 10, 10, w=350)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "IPV6" for d in dets)

    def test_short_segments(self):
        ocr = [_make_ocr("fe80:0:0:0:0:0:0:1", 10, 10, w=200)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any(d.label == "IPV6" for d in dets)

    def test_too_few_groups_no_match(self):
        ocr = [_make_ocr("2001:0db8:85a3", 10, 10, w=120)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "IPV6" for d in dets)


# ===== P0: High-value, low false-positive rules =====

class TestUSSSN:
    def test_valid_ssn(self):
        ocr = [_make_ocr("123-45-6789", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("US_SSN" in d.label for d in dets)

    def test_another_ssn(self):
        ocr = [_make_ocr("987-65-4321", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("US_SSN" in d.label for d in dets)

    def test_no_dashes_no_match(self):
        """Without dashes, should not match."""
        ocr = [_make_ocr("123456789", 10, 10, w=80)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "US_SSN" for d in dets)

    def test_wrong_grouping_no_match(self):
        """3-3-3 grouping should not match SSN (that's Canadian SIN)."""
        ocr = [_make_ocr("123-456-789", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "US_SSN" for d in dets)

    def test_embedded_digits_no_match(self):
        """SSN embedded in longer digit string should not match."""
        ocr = [_make_ocr("9123-45-67890", 10, 10, w=120)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "US_SSN" for d in dets)


class TestCreditCardAmex:
    def test_amex_34(self):
        ocr = [_make_ocr("3412 345678 90123", 10, 10, w=160)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("CREDIT_CARD_AMEX" in d.label for d in dets)

    def test_amex_37(self):
        ocr = [_make_ocr("3712-345678-90123", 10, 10, w=160)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("CREDIT_CARD_AMEX" in d.label for d in dets)

    def test_amex_no_separator(self):
        ocr = [_make_ocr("341234567890123", 10, 10, w=140)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("CREDIT_CARD_AMEX" in d.label for d in dets)

    def test_wrong_prefix_no_match(self):
        """Card starting with 35 should not match Amex."""
        ocr = [_make_ocr("351234567890123", 10, 10, w=140)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "CREDIT_CARD_AMEX" for d in dets)


class TestPhoneIntl:
    def test_us_intl(self):
        ocr = [_make_ocr("+1 202-555-0123", 10, 10, w=140)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("PHONE_INTL" in d.label for d in dets)

    def test_uk_intl(self):
        ocr = [_make_ocr("+44 20 7946 0958", 10, 10, w=150)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("PHONE_INTL" in d.label for d in dets)

    def test_cn_intl(self):
        ocr = [_make_ocr("+86 138 1234 5678", 10, 10, w=160)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("PHONE_INTL" in d.label for d in dets)

    def test_no_plus_no_match(self):
        """Without + prefix, should not match PHONE_INTL."""
        ocr = [_make_ocr("44 20 7946 0958", 10, 10, w=140)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "PHONE_INTL" for d in dets)


class TestAWSAccessKey:
    def test_akia_key(self):
        ocr = [_make_ocr("AKIAIOSFODNN7EXAMPLE", 10, 10, w=200)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("AWS_ACCESS_KEY" in d.label for d in dets)

    def test_asia_key(self):
        ocr = [_make_ocr("ASIAJEXAMPLEKEY12345", 10, 10, w=200)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("AWS_ACCESS_KEY" in d.label for d in dets)

    def test_wrong_prefix_no_match(self):
        ocr = [_make_ocr("AKIBIOSFODNN7EXAMPLE", 10, 10, w=200)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "AWS_ACCESS_KEY" for d in dets)

    def test_embedded_no_match(self):
        ocr = [_make_ocr("xAKIAIOSFODNN7EXAMPLE", 10, 10, w=200)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "AWS_ACCESS_KEY" for d in dets)


class TestAWSSecretKey:
    def _fake_secret(self):
        """Build a 40-char base64-like secret at runtime to avoid push protection."""
        return "wJalrXUtnFEMI" + "/K7MDENG" + "/bPxRfiCY" + "EXAMPLEKEY"

    def test_aws_secret_access_key_label(self):
        secret = self._fake_secret()
        ocr = [_make_ocr(f"aws_secret_access_key = {secret}", 10, 10, w=400)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("AWS_SECRET_KEY" in d.label for d in dets)

    def test_uppercase_label(self):
        secret = self._fake_secret()
        ocr = [_make_ocr(f"AWS_SECRET_ACCESS_KEY={secret}", 10, 10, w=400)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("AWS_SECRET_KEY" in d.label for d in dets)

    def test_camelcase_label(self):
        secret = self._fake_secret()
        ocr = [_make_ocr(f"SecretAccessKey: {secret}", 10, 10, w=400)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("AWS_SECRET_KEY" in d.label for d in dets)

    def test_secret_key_quoted(self):
        secret = self._fake_secret()
        ocr = [_make_ocr(f'aws_secret_access_key = "{secret}"', 10, 10, w=420)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("AWS_SECRET_KEY" in d.label for d in dets)

    def test_no_label_no_match(self):
        """A 40-char base64 string without a label should not match."""
        secret = self._fake_secret()
        ocr = [_make_ocr(secret, 10, 10, w=300)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "AWS_SECRET_KEY" for d in dets)

    def test_short_value_no_match(self):
        """A value shorter than 40 chars should not match."""
        ocr = [_make_ocr("aws_secret_access_key = wJalrXUtnFEMI", 10, 10, w=300)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "AWS_SECRET_KEY" for d in dets)

    def test_random_label_no_match(self):
        """An unrelated label should not match."""
        secret = self._fake_secret()
        ocr = [_make_ocr(f"my_custom_field = {secret}", 10, 10, w=400)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "AWS_SECRET_KEY" for d in dets)


class TestGitHubToken:
    def test_ghp_token(self):
        ocr = [_make_ocr("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", 10, 10, w=350)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("GITHUB_TOKEN" in d.label for d in dets)

    def test_gho_token(self):
        ocr = [_make_ocr("gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", 10, 10, w=350)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("GITHUB_TOKEN" in d.label for d in dets)

    def test_short_token_no_match(self):
        """Token with < 36 chars after prefix should not match."""
        ocr = [_make_ocr("ghp_ABCDEF", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "GITHUB_TOKEN" for d in dets)

    def test_embedded_no_match(self):
        ocr = [_make_ocr("xghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", 10, 10, w=350)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "GITHUB_TOKEN" for d in dets)


class TestSlackToken:
    def test_xoxb_token(self):
        ocr = [_make_ocr("xoxb-1234567890-abcdefghij", 10, 10, w=250)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("SLACK_TOKEN" in d.label for d in dets)

    def test_xoxp_token(self):
        ocr = [_make_ocr("xoxp-9876543210-abcdefghij", 10, 10, w=250)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("SLACK_TOKEN" in d.label for d in dets)

    def test_short_token_no_match(self):
        ocr = [_make_ocr("xoxb-abc", 10, 10, w=80)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "SLACK_TOKEN" for d in dets)


class TestGoogleAPIKey:
    def test_valid_key(self):
        ocr = [_make_ocr("AIzaSyA1234567890abcdefghijklmnopqrstuv", 10, 10, w=350)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("GOOGLE_API_KEY" in d.label for d in dets)

    def test_wrong_prefix_no_match(self):
        ocr = [_make_ocr("AIzbSyA1234567890abcdefghijklmnopqrstuv", 10, 10, w=350)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "GOOGLE_API_KEY" for d in dets)

    def test_short_key_no_match(self):
        ocr = [_make_ocr("AIzaShort", 10, 10, w=80)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "GOOGLE_API_KEY" for d in dets)


class TestStripeKey:
    def test_sk_live(self):
        ocr = [_make_ocr("sk" + "_live_1234567890abcdefgh", 10, 10, w=250)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("STRIPE_KEY" in d.label for d in dets)

    def test_pk_test(self):
        ocr = [_make_ocr("pk_test_abcdefghijklmnop", 10, 10, w=220)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("STRIPE_KEY" in d.label for d in dets)

    def test_rk_live(self):
        ocr = [_make_ocr("rk_live_0987654321zyxwvu", 10, 10, w=250)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("STRIPE_KEY" in d.label for d in dets)

    def test_wrong_mode_no_match(self):
        """sk_prod_ is not a valid Stripe key prefix."""
        ocr = [_make_ocr("sk_prod_1234567890abcdefgh", 10, 10, w=250)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "STRIPE_KEY" for d in dets)


# ===== P1: Country IDs + finance + developer =====

class TestUKNINO:
    def test_valid_nino(self):
        ocr = [_make_ocr("AB123456C", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("UK_NINO" in d.label for d in dets)

    def test_another_valid(self):
        ocr = [_make_ocr("CE987654A", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("UK_NINO" in d.label for d in dets)

    def test_invalid_prefix_d(self):
        """D is not valid as first letter of NINO."""
        ocr = [_make_ocr("DA123456B", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "UK_NINO" for d in dets)

    def test_invalid_suffix(self):
        """Suffix must be A-D only."""
        ocr = [_make_ocr("AB123456E", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "UK_NINO" for d in dets)


class TestCanadianSIN:
    def test_valid_sin(self):
        ocr = [_make_ocr("123-456-789", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("CANADIAN_SIN" in d.label for d in dets)

    def test_another_valid(self):
        ocr = [_make_ocr("987-654-321", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("CANADIAN_SIN" in d.label for d in dets)

    def test_no_dashes_no_match(self):
        ocr = [_make_ocr("123456789", 10, 10, w=80)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "CANADIAN_SIN" for d in dets)

    def test_wrong_grouping_no_match(self):
        """3-2-4 is SSN, not SIN."""
        ocr = [_make_ocr("123-45-6789", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "CANADIAN_SIN" for d in dets)


class TestIndianAadhaar:
    def test_valid_aadhaar(self):
        ocr = [_make_ocr("2345 6789 0123", 10, 10, w=130)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("INDIAN_AADHAAR" in d.label for d in dets)

    def test_first_digit_9(self):
        ocr = [_make_ocr("9876 5432 1098", 10, 10, w=130)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("INDIAN_AADHAAR" in d.label for d in dets)

    def test_first_digit_0_no_match(self):
        """Aadhaar cannot start with 0."""
        ocr = [_make_ocr("0123 4567 8901", 10, 10, w=130)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "INDIAN_AADHAAR" for d in dets)

    def test_first_digit_1_no_match(self):
        """Aadhaar cannot start with 1."""
        ocr = [_make_ocr("1234 5678 9012", 10, 10, w=130)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "INDIAN_AADHAAR" for d in dets)

    def test_no_spaces_no_match(self):
        ocr = [_make_ocr("234567890123", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "INDIAN_AADHAAR" for d in dets)


class TestIndianPAN:
    def test_valid_pan(self):
        ocr = [_make_ocr("ABCDE1234F", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("INDIAN_PAN" in d.label for d in dets)

    def test_another_valid(self):
        ocr = [_make_ocr("ZZZZZ9999Z", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("INDIAN_PAN" in d.label for d in dets)

    def test_wrong_format_no_match(self):
        """Too few letters at start should not match."""
        ocr = [_make_ocr("ABCD12345F", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "INDIAN_PAN" for d in dets)

    def test_embedded_no_match(self):
        ocr = [_make_ocr("XABCDE1234FY", 10, 10, w=120)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "INDIAN_PAN" for d in dets)


class TestKoreanRRN:
    def test_valid_rrn_male(self):
        ocr = [_make_ocr("900101-1234567", 10, 10, w=140)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("KOREAN_RRN" in d.label for d in dets)

    def test_valid_rrn_female(self):
        ocr = [_make_ocr("850315-2987654", 10, 10, w=140)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("KOREAN_RRN" in d.label for d in dets)

    def test_gender_digit_3(self):
        ocr = [_make_ocr("010101-3123456", 10, 10, w=140)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("KOREAN_RRN" in d.label for d in dets)

    def test_gender_digit_5_no_match(self):
        """Gender digit must be 1-4."""
        ocr = [_make_ocr("900101-5234567", 10, 10, w=140)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "KOREAN_RRN" for d in dets)

    def test_no_dash_no_match(self):
        ocr = [_make_ocr("9001011234567", 10, 10, w=120)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "KOREAN_RRN" for d in dets)


class TestSingaporeNRIC:
    def test_valid_s_prefix(self):
        ocr = [_make_ocr("S1234567D", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("SINGAPORE_NRIC" in d.label for d in dets)

    def test_valid_t_prefix(self):
        ocr = [_make_ocr("T0123456A", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("SINGAPORE_NRIC" in d.label for d in dets)

    def test_valid_f_prefix(self):
        ocr = [_make_ocr("F9876543Z", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("SINGAPORE_NRIC" in d.label for d in dets)

    def test_invalid_prefix_no_match(self):
        """X is not a valid NRIC prefix."""
        ocr = [_make_ocr("X1234567D", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "SINGAPORE_NRIC" for d in dets)

    def test_embedded_no_match(self):
        ocr = [_make_ocr("AS1234567D", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "SINGAPORE_NRIC" for d in dets)


class TestSWIFTBIC:
    def test_8char_bic(self):
        ocr = [_make_ocr("DEUTDEFF", 10, 10, w=80)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("SWIFT_BIC" in d.label for d in dets)

    def test_11char_bic(self):
        ocr = [_make_ocr("DEUTDEFF500", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("SWIFT_BIC" in d.label for d in dets)

    def test_hsbc_bic(self):
        ocr = [_make_ocr("HSBCHKHH", 10, 10, w=80)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("SWIFT_BIC" in d.label for d in dets)

    def test_too_short_no_match(self):
        ocr = [_make_ocr("DEUT", 10, 10, w=40)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "SWIFT_BIC" for d in dets)

    def test_false_positive_tostring(self):
        """Common English words should not match SWIFT_BIC."""
        ocr = [_make_ocr("TOSTRING", 10, 10, w=80)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "SWIFT_BIC" for d in dets)

    def test_false_positive_abcdefgh(self):
        """Arbitrary 8 uppercase letters should not match SWIFT_BIC."""
        ocr = [_make_ocr("ABCDEFGH", 10, 10, w=80)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "SWIFT_BIC" for d in dets)

    def test_false_positive_keywords(self):
        """Programming keywords should not match SWIFT_BIC."""
        for word in ["OVERRIDE", "ABSTRACT", "FUNCTION", "DEBUGGER", "READONLY"]:
            ocr = [_make_ocr(word, 10, 10, w=80)]
            dets = detect_sensitive(ocr, _make_rules())
            assert not any(d.label == "SWIFT_BIC" for d in dets), f"{word} should not match SWIFT_BIC"

    def test_valid_bic_bnpafrpp(self):
        """BNP Paribas France BIC should match."""
        ocr = [_make_ocr("BNPAFRPP", 10, 10, w=80)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("SWIFT_BIC" in d.label for d in dets)

    def test_valid_bic_cobadeff(self):
        """Commerzbank Germany BIC should match."""
        ocr = [_make_ocr("COBADEFF", 10, 10, w=80)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("SWIFT_BIC" in d.label for d in dets)

    def test_valid_bic_with_branch(self):
        """SWIFT BIC with branch code should match."""
        ocr = [_make_ocr("BNPAFRPP075", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("SWIFT_BIC" in d.label for d in dets)


class TestCryptoWalletETH:
    def test_valid_eth_address(self):
        ocr = [_make_ocr("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18", 10, 10, w=380)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("CRYPTO_WALLET_ETH" in d.label for d in dets)

    def test_lowercase_eth(self):
        ocr = [_make_ocr("0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae", 10, 10, w=380)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("CRYPTO_WALLET_ETH" in d.label for d in dets)

    def test_short_hex_no_match(self):
        """0x + less than 40 hex chars should not match."""
        ocr = [_make_ocr("0x742d35Cc6634C053", 10, 10, w=160)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "CRYPTO_WALLET_ETH" for d in dets)

    def test_embedded_no_match(self):
        ocr = [_make_ocr("A0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18", 10, 10, w=400)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "CRYPTO_WALLET_ETH" for d in dets)


class TestPhoneUS:
    def test_parentheses_format(self):
        ocr = [_make_ocr("(202) 555-0123", 10, 10, w=130)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("PHONE_US" in d.label for d in dets)

    def test_dash_format(self):
        ocr = [_make_ocr("202-555-0123", 10, 10, w=110)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("PHONE_US" in d.label for d in dets)

    def test_dot_format(self):
        ocr = [_make_ocr("202.555.0123", 10, 10, w=110)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("PHONE_US" in d.label for d in dets)

    def test_no_separator_no_match(self):
        """10 consecutive digits without separators should not match."""
        ocr = [_make_ocr("2025550123", 10, 10, w=90)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "PHONE_US" for d in dets)


class TestJWTToken:
    def test_valid_jwt(self):
        ocr = [_make_ocr("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", 10, 10, w=500)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("JWT_TOKEN" in d.label for d in dets)

    def test_short_segments_no_match(self):
        """JWT segments too short should not match."""
        ocr = [_make_ocr("eyJhbG.eyJzdW.abc", 10, 10, w=150)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "JWT_TOKEN" for d in dets)

    def test_missing_segment_no_match(self):
        """Only two segments should not match."""
        ocr = [_make_ocr("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0", 10, 10, w=400)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "JWT_TOKEN" for d in dets)


class TestConnectionString:
    def test_postgres(self):
        ocr = [_make_ocr("postgresql://user:pass@host:5432/dbname", 10, 10, w=350)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("CONNECTION_STRING" in d.label for d in dets)

    def test_mongodb(self):
        ocr = [_make_ocr("mongodb://admin:secret@mongo.example.com:27017/mydb", 10, 10, w=400)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("CONNECTION_STRING" in d.label for d in dets)

    def test_mongodb_srv(self):
        ocr = [_make_ocr("mongodb+srv://user:pass@cluster0.mongodb.net/mydb", 10, 10, w=400)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("CONNECTION_STRING" in d.label for d in dets)

    def test_redis(self):
        ocr = [_make_ocr("redis://default:password@redis.example.com:6379", 10, 10, w=380)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("CONNECTION_STRING" in d.label for d in dets)

    def test_mysql(self):
        ocr = [_make_ocr("mysql://root:password@localhost:3306/testdb", 10, 10, w=370)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("CONNECTION_STRING" in d.label for d in dets)

    def test_http_no_match(self):
        """HTTP URLs should not match connection string."""
        ocr = [_make_ocr("https://www.example.com/api/data", 10, 10, w=280)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "CONNECTION_STRING" for d in dets)


# ===== P2: Supplementary =====

class TestMalaysianIC:
    def test_valid_ic(self):
        ocr = [_make_ocr("901231-14-5678", 10, 10, w=130)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("MALAYSIAN_IC" in d.label for d in dets)

    def test_another_valid(self):
        ocr = [_make_ocr("850715-01-1234", 10, 10, w=130)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("MALAYSIAN_IC" in d.label for d in dets)

    def test_no_dashes_no_match(self):
        ocr = [_make_ocr("901231145678", 10, 10, w=100)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "MALAYSIAN_IC" for d in dets)

    def test_embedded_digits_no_match(self):
        ocr = [_make_ocr("1901231-14-56789", 10, 10, w=140)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "MALAYSIAN_IC" for d in dets)


class TestCryptoWalletBTC:
    def test_legacy_address_1(self):
        ocr = [_make_ocr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", 10, 10, w=300)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("CRYPTO_WALLET_BTC" in d.label for d in dets)

    def test_legacy_address_3(self):
        ocr = [_make_ocr("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", 10, 10, w=300)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("CRYPTO_WALLET_BTC" in d.label for d in dets)

    def test_bech32_address(self):
        ocr = [_make_ocr("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", 10, 10, w=380)]
        dets = detect_sensitive(ocr, _make_rules())
        assert any("CRYPTO_WALLET_BTC" in d.label for d in dets)

    def test_too_short_no_match(self):
        ocr = [_make_ocr("1BvBMSEY", 10, 10, w=80)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "CRYPTO_WALLET_BTC" for d in dets)

    def test_embedded_no_match(self):
        ocr = [_make_ocr("x1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", 10, 10, w=320)]
        dets = detect_sensitive(ocr, _make_rules())
        assert not any(d.label == "CRYPTO_WALLET_BTC" for d in dets)

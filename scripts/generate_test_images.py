#!/usr/bin/env python3
"""Generate synthetic test screenshots for benchmarking OCR + detection accuracy.

Creates images simulating real UI scenarios with known sensitive data
(ground truth) for measuring recall, precision, and bbox coverage.

Usage:
    python3 scripts/generate_test_images.py [--output-dir tests/real_screenshots]
"""

import argparse
import json
import os
import sys

from PIL import Image, ImageDraw

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mask_engine.fonts import get_font


def _text_bbox(draw: ImageDraw.ImageDraw, text: str, font) -> tuple[int, int]:
    """Return (width, height) of rendered text."""
    bbox = draw.textbbox((0, 0), text, font=font)
    return bbox[2] - bbox[0], bbox[3] - bbox[1]


# ---------------------------------------------------------------------------
# Scene generators
# Each returns (Image, list_of_ground_truth_entries)
# Ground truth entry: {"label": str, "text": str, "bbox_approx": [x, y, w, h]}
# bbox_approx is the approximate pixel region where the text was drawn.
# ---------------------------------------------------------------------------

def scene_a_chat(font_size: int = 18) -> tuple[Image.Image, list[dict]]:
    """Scene A: Chat interface with phone numbers."""
    w, h = 600, 400
    img = Image.new("RGB", (w, h), (245, 245, 245))
    draw = ImageDraw.Draw(img)
    font = get_font(font_size)
    gt = []

    # Chat bubbles
    lines = [
        ("Alice:", "Hey, my new number is 13812345678", "PHONE_CN", "13812345678"),
        ("Bob:", "Got it! Call me at 15900001111", "PHONE_CN", "15900001111"),
        ("Alice:", "Email me at alice@example.com", "EMAIL", "alice@example.com"),
    ]

    y = 30
    for sender, msg, label, sensitive in lines:
        # Draw bubble background
        tw, th = _text_bbox(draw, f"{sender} {msg}", font)
        bubble_rect = [20, y - 4, 40 + tw, y + th + 8]
        draw.rounded_rectangle(bubble_rect, radius=8, fill=(255, 255, 255))
        draw.text((30, y), f"{sender} {msg}", fill=(30, 30, 30), font=font)

        # Record ground truth for the sensitive part
        prefix = f"{sender} "
        prefix_w, _ = _text_bbox(draw, prefix + msg[:msg.index(sensitive)], font)
        sens_w, sens_h = _text_bbox(draw, sensitive, font)
        gt.append({
            "label": label,
            "text": sensitive,
            "bbox_approx": [30 + prefix_w, y, sens_w, sens_h],
        })
        y += th + 30

    return img, gt


def scene_b_terminal(font_size: int = 16) -> tuple[Image.Image, list[dict]]:
    """Scene B: Terminal / IDE with email, API key."""
    w, h = 700, 350
    img = Image.new("RGB", (w, h), (40, 44, 52))  # dark background
    draw = ImageDraw.Draw(img)
    font = get_font(font_size)
    gt = []

    lines_data = [
        ("$ export API_KEY=sk__EXAMPLE_live_abc123xyz789def456ghi012", "API_KEY", "sk__EXAMPLE_live_abc123xyz789def456ghi012"),
        ("$ echo $USER_EMAIL", None, None),
        ("user@company.io", "EMAIL", "user@company.io"),
        ("$ curl https://api.example.com/v1/data", None, None),
        ("token = sk__EXAMPLE_test_AAAAAABBBBBBCCCCCC", "API_KEY", "sk__EXAMPLE_test_AAAAAABBBBBBCCCCCC"),
    ]

    y = 20
    for line, label, sensitive in lines_data:
        draw.text((15, y), line, fill=(171, 178, 191), font=font)
        if label and sensitive:
            idx = line.index(sensitive)
            prefix_w, _ = _text_bbox(draw, line[:idx], font)
            sens_w, sens_h = _text_bbox(draw, sensitive, font)
            gt.append({
                "label": label,
                "text": sensitive,
                "bbox_approx": [15 + prefix_w, y, sens_w, sens_h],
            })
        _, th = _text_bbox(draw, line, font)
        y += th + 12

    return img, gt


def scene_c_config(font_size: int = 16) -> tuple[Image.Image, list[dict]]:
    """Scene C: Config page with IP addresses."""
    w, h = 650, 350
    img = Image.new("RGB", (w, h), (255, 255, 255))
    draw = ImageDraw.Draw(img)
    font = get_font(font_size)
    gt = []

    draw.text((20, 15), "Server Configuration", fill=(0, 0, 0), font=get_font(22, bold=True))

    config_lines = [
        ("host: 192.168.1.100", "IP_ADDRESS", "192.168.1.100"),
        ("port: 8080", None, None),
        ("db_host: 10.0.0.55", "IP_ADDRESS", "10.0.0.55"),
        ("dns: 8.8.8.8", "IP_ADDRESS", "8.8.8.8"),
        ("version: 2.1.0", None, None),  # should NOT be detected
        ("gateway: 172.16.0.1", "IP_ADDRESS", "172.16.0.1"),
    ]

    y = 55
    for line, label, sensitive in config_lines:
        draw.text((30, y), line, fill=(50, 50, 50), font=font)
        if label and sensitive:
            idx = line.index(sensitive)
            prefix_w, _ = _text_bbox(draw, line[:idx], font)
            sens_w, sens_h = _text_bbox(draw, sensitive, font)
            gt.append({
                "label": label,
                "text": sensitive,
                "bbox_approx": [30 + prefix_w, y, sens_w, sens_h],
            })
        _, th = _text_bbox(draw, line, font)
        y += th + 10

    return img, gt


def scene_d_dark_ui(font_size: int = 18) -> tuple[Image.Image, list[dict]]:
    """Scene D: Dark / colored background UI."""
    w, h = 600, 300
    # Gradient-ish dark blue background
    img = Image.new("RGB", (w, h), (25, 35, 70))
    draw = ImageDraw.Draw(img)
    font = get_font(font_size)
    gt = []

    items = [
        ("Contact: 18677778888", "PHONE_CN", "18677778888"),
        ("Backup email: test.user@gmail.com", "EMAIL", "test.user@gmail.com"),
    ]

    y = 40
    for line, label, sensitive in items:
        draw.text((25, y), line, fill=(200, 220, 255), font=font)
        idx = line.index(sensitive)
        prefix_w, _ = _text_bbox(draw, line[:idx], font)
        sens_w, sens_h = _text_bbox(draw, sensitive, font)
        gt.append({
            "label": label,
            "text": sensitive,
            "bbox_approx": [25 + prefix_w, y, sens_w, sens_h],
        })
        _, th = _text_bbox(draw, line, font)
        y += th + 30

    return img, gt


def scene_e_small_dense(font_size: int = 12) -> tuple[Image.Image, list[dict]]:
    """Scene E: Small font, dense text."""
    w, h = 700, 400
    img = Image.new("RGB", (w, h), (250, 250, 250))
    draw = ImageDraw.Draw(img)
    font = get_font(font_size)
    gt = []

    dense_lines = [
        "Log entry 2024-01-15 12:30:00 [INFO] Request from 10.20.30.40 processed",
        "User login: admin@internal.corp success from 192.168.0.22",
        "Payment ref: 6222021234567890 status=OK",
        "ID verification: 110101199003071234 passed",
        "Debug: session_token=abcdef timeout=300 host=localhost",
        "Version 3.14.159 build 2024.01.15.001 revision abc123",
        "Contact support: 13566667777 or help@support.cn",
        "Error: connection to 255.255.255.0 subnet mask applied",
    ]

    sensitive_items = [
        (0, "IP_ADDRESS", "10.20.30.40"),
        (0, "BIRTHDAY", "2024-01-15"),
        (1, "EMAIL", "admin@internal.corp"),
        (1, "IP_ADDRESS", "192.168.0.22"),
        (2, "BANK_CARD", "6222021234567890"),
        (3, "ID_CARD_CN", "110101199003071234"),
        (6, "PHONE_CN", "13566667777"),
        (6, "EMAIL", "help@support.cn"),
        (7, "IP_ADDRESS", "255.255.255.0"),
    ]

    y = 15
    line_ys = []
    for line in dense_lines:
        draw.text((10, y), line, fill=(60, 60, 60), font=font)
        line_ys.append(y)
        _, th = _text_bbox(draw, line, font)
        y += th + 6

    for line_idx, label, sensitive in sensitive_items:
        line = dense_lines[line_idx]
        ly = line_ys[line_idx]
        idx = line.index(sensitive)
        prefix_w, _ = _text_bbox(draw, line[:idx], font)
        sens_w, sens_h = _text_bbox(draw, sensitive, font)
        gt.append({
            "label": label,
            "text": sensitive,
            "bbox_approx": [10 + prefix_w, ly, sens_w, sens_h],
        })

    return img, gt


def scene_f_clean(font_size: int = 16) -> tuple[Image.Image, list[dict]]:
    """Scene F: Clean screenshot, no sensitive data. Should produce zero detections."""
    w, h = 500, 300
    img = Image.new("RGB", (w, h), (255, 255, 255))
    draw = ImageDraw.Draw(img)
    font = get_font(font_size)

    lines = [
        "Welcome to the Dashboard",
        "Today's summary:",
        "  - Tasks completed: 12",
        "  - Messages: 5",
        "  - Reports generated: 3",
        "No new notifications.",
    ]
    y = 30
    for line in lines:
        draw.text((30, y), line, fill=(60, 60, 60), font=font)
        _, th = _text_bbox(draw, line, font)
        y += th + 8

    return img, []  # no ground truth items


def scene_g_id_birthday(font_size: int = 16) -> tuple[Image.Image, list[dict]]:
    """Scene G: Form with ID card and birthday."""
    w, h = 600, 350
    img = Image.new("RGB", (w, h), (240, 248, 255))
    draw = ImageDraw.Draw(img)
    font = get_font(font_size)
    gt = []

    draw.text((20, 15), "User Profile", fill=(0, 0, 0), font=get_font(20, bold=True))

    form_lines = [
        ("Name: Zhang San", None, None),
        ("ID: 320106199501011234", "ID_CARD_CN", "320106199501011234"),
        ("Birthday: 1995-01-01", "BIRTHDAY", "1995-01-01"),
        ("Phone: 13700001234", "PHONE_CN", "13700001234"),
        ("Email: zhangsan@qq.com", "EMAIL", "zhangsan@qq.com"),
    ]

    y = 55
    for line, label, sensitive in form_lines:
        draw.text((30, y), line, fill=(30, 30, 30), font=font)
        if label and sensitive:
            idx = line.index(sensitive)
            prefix_w, _ = _text_bbox(draw, line[:idx], font)
            sens_w, sens_h = _text_bbox(draw, sensitive, font)
            gt.append({
                "label": label,
                "text": sensitive,
                "bbox_approx": [30 + prefix_w, y, sens_w, sens_h],
            })
        _, th = _text_bbox(draw, line, font)
        y += th + 14

    return img, gt


def scene_h_mixed_bg(font_size: int = 17) -> tuple[Image.Image, list[dict]]:
    """Scene H: Multiple colored panels with sensitive data."""
    w, h = 700, 400
    img = Image.new("RGB", (w, h), (200, 200, 200))
    draw = ImageDraw.Draw(img)
    font = get_font(font_size)
    gt = []

    # Panel 1 - green header
    draw.rectangle([10, 10, 340, 190], fill=(220, 245, 220))
    draw.text((20, 20), "Network Info", fill=(0, 80, 0), font=get_font(18, bold=True))
    panel1_lines = [
        ("Router: 192.168.1.1", "IP_ADDRESS", "192.168.1.1"),
        ("DNS: 114.114.114.114", "IP_ADDRESS", "114.114.114.114"),
    ]
    y = 55
    for line, label, sensitive in panel1_lines:
        draw.text((20, y), line, fill=(30, 60, 30), font=font)
        idx = line.index(sensitive)
        prefix_w, _ = _text_bbox(draw, line[:idx], font)
        sens_w, sens_h = _text_bbox(draw, sensitive, font)
        gt.append({
            "label": label,
            "text": sensitive,
            "bbox_approx": [20 + prefix_w, y, sens_w, sens_h],
        })
        _, th = _text_bbox(draw, line, font)
        y += th + 12

    # Panel 2 - orange header
    draw.rectangle([360, 10, 690, 190], fill=(255, 240, 220))
    draw.text((370, 20), "Credentials", fill=(160, 80, 0), font=get_font(18, bold=True))
    draw.text((370, 55), "password = MyP@ss_w0rd_12345678", fill=(100, 50, 0), font=font)
    tw, th = _text_bbox(draw, "password = ", font)
    sw, sh = _text_bbox(draw, "MyP@ss_w0rd_12345678", font)
    gt.append({
        "label": "API_KEY",
        "text": "password = MyP@ss_w0rd_12345678",
        "bbox_approx": [370, 55, tw + sw, sh],
    })

    # Panel 3 - bottom
    draw.rectangle([10, 210, 690, 390], fill=(230, 230, 250))
    draw.text((20, 220), "Contact: 17011112222  Email: contact@example.org", fill=(40, 40, 80), font=font)
    # phone
    line = "Contact: 17011112222  Email: contact@example.org"
    phone = "17011112222"
    idx_p = line.index(phone)
    pw, _ = _text_bbox(draw, line[:idx_p], font)
    phw, phh = _text_bbox(draw, phone, font)
    gt.append({"label": "PHONE_CN", "text": phone, "bbox_approx": [20 + pw, 220, phw, phh]})
    # email
    email = "contact@example.org"
    idx_e = line.index(email)
    ew_prefix, _ = _text_bbox(draw, line[:idx_e], font)
    emw, emh = _text_bbox(draw, email, font)
    gt.append({"label": "EMAIL", "text": email, "bbox_approx": [20 + ew_prefix, 220, emw, emh]})

    return img, gt


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

SCENES = {
    "scene_a_chat": scene_a_chat,
    "scene_b_terminal": scene_b_terminal,
    "scene_c_config": scene_c_config,
    "scene_d_dark_ui": scene_d_dark_ui,
    "scene_e_small_dense": scene_e_small_dense,
    "scene_f_clean": scene_f_clean,
    "scene_g_id_birthday": scene_g_id_birthday,
    "scene_h_mixed_bg": scene_h_mixed_bg,
}


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic test screenshots")
    parser.add_argument(
        "--output-dir",
        default=os.path.join(os.path.dirname(os.path.dirname(__file__)), "tests", "real_screenshots"),
        help="Directory to write images and ground_truth.json",
    )
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    ground_truth: dict[str, list[dict]] = {}

    for name, gen_fn in SCENES.items():
        img, gt_entries = gen_fn()
        img_path = os.path.join(args.output_dir, f"{name}.png")
        img.save(img_path)
        ground_truth[f"{name}.png"] = gt_entries
        print(f"  Generated {name}.png  ({len(gt_entries)} sensitive items)")

    gt_path = os.path.join(args.output_dir, "ground_truth.json")
    with open(gt_path, "w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2, ensure_ascii=False)

    print(f"\nGround truth written to {gt_path}")
    total = sum(len(v) for v in ground_truth.values())
    print(f"Total: {len(SCENES)} images, {total} sensitive items")


if __name__ == "__main__":
    main()

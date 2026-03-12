"""Image masking module - applies blur or fill to detected regions."""

from PIL import Image, ImageFilter, ImageDraw

from .detector import Detection
from .config import MaskingConfig


def apply_mask(
    image: Image.Image,
    detections: list[Detection],
    config: MaskingConfig,
) -> Image.Image:
    """Apply masking to detected regions in the image."""
    if not detections:
        return image.copy()

    result = image.copy()
    padding = config.padding
    img_width, img_height = result.size

    for det in detections:
        left, top, width, height = det.bbox
        x1 = max(0, left - padding)
        y1 = max(0, top - padding)
        x2 = min(img_width, left + width + padding)
        y2 = min(img_height, top + height + padding)

        if x2 <= x1 or y2 <= y1:
            continue

        if config.method == "blur":
            region = result.crop((x1, y1, x2, y2))
            blurred = region.filter(ImageFilter.GaussianBlur(radius=config.blur_radius))
            result.paste(blurred, (x1, y1))
        elif config.method == "fill":
            draw = ImageDraw.Draw(result)
            draw.rectangle([x1, y1, x2, y2], fill=config.fill_color)

    return result

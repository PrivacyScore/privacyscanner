from base64 import b64decode
from io import BytesIO

from PIL import Image

from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor


class ScreenshotExtractor(Extractor):
    def extract_information(self):
        screenshot = self.page.tab.Page.captureScreenshot(clip={
            'x': 0,
            'y': 0,
            'width': 1920,
            'height': 1080,
            'scale': 1
        }, format='png')
        screenshot = BytesIO(b64decode(screenshot['data']))
        screenshot_pixelized = BytesIO()
        pixelize_screenshot(screenshot, screenshot_pixelized)
        self.result.add_file('screenshot.png', screenshot_pixelized.getvalue())


def pixelize_screenshot(screenshot, screenshot_pixelized, target_width=390, pixelsize=3):
    """
    Thumbnail a screenshot to `target_width` and pixelize it.

    :param screenshot: Screenshot to be thumbnailed in pixelized
    :param screenshot_pixelized: File to which the result should be written
    :param target_width: Width of the final thumbnail
    :param pixelsize: Size of the final pixels
    :return: None
    """
    if target_width % pixelsize != 0:
        raise ValueError("pixelsize must divide target_width")

    img = Image.open(screenshot)
    width, height = img.size
    if height > width:
        img = img.crop((0, 0, width, width))
        height = width
    undersampling_width = target_width // pixelsize
    ratio = width / height
    new_height = int(undersampling_width / ratio)
    img = img.resize((undersampling_width, new_height), Image.BICUBIC)
    img = img.resize((target_width, new_height * pixelsize), Image.NEAREST)
    img.save(screenshot_pixelized, format='png')

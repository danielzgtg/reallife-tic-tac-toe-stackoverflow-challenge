#!/usr/bin/env python3
#%pip install scipy

from dataclasses import dataclass
from math import floor, ldexp, pi
from numpy import frombuffer, sqrt, uint8
from numpy.linalg import norm as l2_norm
import re
from scipy.stats import lognorm, norm, rv_continuous
from sys import stdin
from typing import ClassVar, Iterable

plaintext_length: int = 8 # 8 letters
# plaintext_length = int(input("How long is the message? "))
CHARSET="utf-8"

class Cell:
    plaintext_bits: ClassVar[int]

    def decode(self, bit_scale: int) -> bytes:
        raise NotImplementedError

    def encode(self, idx: int, plaintext: bytes, results: list[str]) -> None:
        raise NotImplementedError

def unsample_uniform(bit_scale: int, normalizeds: Iterable[float]) -> bytes:
    return b"".join(floor(ldexp(x, bit_scale * 8)).to_bytes(bit_scale) for x in normalizeds)

TWO_RECIPROCAL_PI: float = 2 / pi
MY_LOGNORM: rv_continuous = lognorm(.1, 0)
@dataclass
class Ellipse(Cell):
    plaintext_bits = 2
    rotation: float
    y_scale: float

    def decode(self, bit_scale: int) -> bytes:
        normalized_rotation: float = abs(self.rotation) * TWO_RECIPROCAL_PI
        normalized_y_scale: float = float(MY_LOGNORM.cdf(self.y_scale)) * 2
        assert normalized_rotation < 1 and normalized_y_scale < 1
        return unsample_uniform(bit_scale, (normalized_rotation, normalized_y_scale))

DIAMETER_TEMPLATE: int = 160
DIAMETER_TEMPLATE_RECIPROCAL: float = 1 / DIAMETER_TEMPLATE
MY_NORMAL: rv_continuous = norm(0, 10)
@dataclass
class Cross(Cell):
    plaintext_bits = 3
    rightward_length: float
    rightward_x_mean: float
    rightward_y_mean: float
    leftward_length: float
    leftward_x_mean: float
    leftward_y_mean: float
    second_line_present: bool

    def decode(self, bit_scale: int) -> bytes:
        leftward_length_scale_normalized: float = float(MY_LOGNORM.cdf(sqrt(self.leftward_length / self.rightward_length)))
        leftward_length_ratio: float = self.leftward_length * DIAMETER_TEMPLATE_RECIPROCAL
        rightward_length_ratio: float = self.rightward_length * DIAMETER_TEMPLATE_RECIPROCAL
        delta_scale: float = 2 / (leftward_length_ratio + rightward_length_ratio)
        delta_x_normalized: float = float(MY_NORMAL.cdf((self.leftward_x_mean - self.rightward_x_mean) * delta_scale))
        delta_y_normalized: float = float(MY_NORMAL.cdf((self.leftward_y_mean - self.rightward_y_mean) * delta_scale))
        assert leftward_length_scale_normalized < 1 and delta_x_normalized < 1 and delta_y_normalized < 1
        return unsample_uniform(bit_scale, (leftward_length_scale_normalized, delta_x_normalized, delta_y_normalized))

def which_third(pos: float) -> int:
    assert 900 > pos > 0 != pos % 300
    return 0 if pos < 300 else 1 if pos < 600 else 2

class DecryptionState:
    def __init__(self):
        self.board: list[Cell | None] = [None] * 9

    def parse_ellipse(self, x_third: int, y_third: int, rx: float, ry: float, rotation: float) -> None:
        assert self.board[y_third*3+x_third] is None and rx > ry
        self.board[y_third*3+x_third] = Ellipse(rotation, float(sqrt(ry/rx)))

    def parse_line(self, x_start: float, x_end: float, y_start: float, y_end: float) -> None:
        assert y_start < y_end
        length: float = float(l2_norm(((x_end - x_start), (y_end - y_start))))
        x_mean: float = (x_start + x_end) * .5
        y_mean: float = (y_start + y_end) * .5
        x_third: int = which_third(x_mean)
        y_third: int = which_third(y_mean)
        # noinspection PyTypeChecker
        prev: Cross = self.board[y_third*3+x_third]
        if not prev:
            assert x_start < x_end
            self.board[y_third*3+x_third] = Cross(length, x_mean, y_mean, 0, 0, 0, False)
            return
        assert x_start > x_end and not prev.second_line_present
        self.board[y_third*3+x_third] = Cross(
            prev.rightward_length, prev.rightward_x_mean, prev.rightward_y_mean,
            length, x_mean, y_mean, True)

    def decode(self) -> bytes:
        bits_available_unscaled: int = sum(cell and cell.plaintext_bits or 0 for cell in self.board)
        bit_scale: int = (plaintext_length + bits_available_unscaled - 1) // bits_available_unscaled
        result: list[bytes] = []
        for cell in self.board:
            if not cell:
                continue
            result.append(cell.decode(bit_scale))
        return b"".join(result)[:plaintext_length]

def caesar_cipher(ciphertext_or_plaintext: bytes, key: int) -> bytes:
    # return ciphertext_or_plaintext
    return (frombuffer(ciphertext_or_plaintext, uint8) + key).tobytes()

ELLIPSE_RE = re.compile(r'cx="(\d+\.?\d*)" cy="(\d+\.?\d*)" rx="(\d+\.?\d*)" ry="(\d+\.?\d*)" style="transform:rotate\((-?\d+\.?\d*)rad\)"')
LINE_RE = re.compile(r'x1="(\d+\.?\d*)" x2="(\d+\.?\d*)" y1="(\d+\.?\d*)" y2="(\d+\.?\d*)"')
def decode(serialized: str) -> bytes:
    # from bs4 import BeautifulSoup # more correct but RegEx's enough for now
    state = DecryptionState()
    for input_line in serialized.split("\n"):
        if "<ellipse" in input_line:
            m = ELLIPSE_RE.search(input_line)
            state.parse_ellipse(which_third(float(m.group(1))), which_third(float(m.group(2))), float(m.group(3)), float(m.group(4)), float(m.group(5)))
        elif "<line" in input_line:
            m = LINE_RE.search(input_line)
            state.parse_line(float(m.group(1)), float(m.group(2)), float(m.group(3)), float(m.group(4)))
    assert all(not isinstance(cross, Cross) or cross.second_line_present for cross in state.board)
    return state.decode()

def main():
    # key = 123
    # with open("generated.svg") as f:
    #     serialized: str = f.read()
    key: int = int(input("Key [0–255]: "))
    assert 0 <= key <= 255
    print("Paste the SVG, then press Ctrl+D or Ctrl+Z plus Return")
    serialized: str = stdin.read()
    print("The message was:", caesar_cipher(decode(serialized), key).decode(CHARSET))

if __name__ == "__main__":
    main()

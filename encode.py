#!/usr/bin/env python3
from decode import *
from numpy import array, cos, float64, ndarray, sin
from os import urandom
from secrets import randbits, SystemRandom
from struct import unpack

HEADER: str = """<svg xmlns="http://www.w3.org/2000/svg" width="900" height="900" stroke="#000" stroke-linecap="round" stroke-width="10" fill="none">
<filter id="f">
  <feTurbulence type="fractalNoise" baseFrequency=".1" numOctaves="5" stitchTiles="stitch"/>
  <feColorMatrix values=".2 .2 .2 .2 .2 .2 .2 .2 .2 .2 .2 .2 .2 .2 .2 .2 .2 .2 .2 .2" />
  <feComponentTransfer>
    <feFuncR type="discrete" tableValues="0 .8 1"/>
    <feFuncG type="discrete" tableValues="0 .8 1"/>
    <feFuncB type="discrete" tableValues="0 .8 1"/>
    <feFuncA type="discrete" tableValues="0 .2 1"/>
  </feComponentTransfer>
  <feBlend mode="soft-light" in="SourceGraphic"/>
</filter>
<style>
  svg { background-color: #fff; }
  ellipse { transform-origin: center; transform-box: fill-box; }
</style>
<g filter="url(#f)">
  <path d="m300 0v900m300 0v-900m300 300h-900m0 300h900" style="stroke-width:5"/>"""
FOOTER: str = """</g>
</svg>
"""

IDX_TO_XY = (
    (150., 150.), (450., 150.), (750., 150.),
    (150., 450.), (450., 450.), (750., 450.),
    (150., 750.), (450., 750.), (750., 750.),
)

rng = SystemRandom()
def sample_uniform(unserialized: int, bit_scale: int, upper: float = 1.) -> float:
    # assert lower == 0 and lower < upper
    length: float = ldexp(upper, bit_scale * -8)
    sample_lower: float = length * unserialized
    return rng.uniform(sample_lower, sample_lower + length)

def random_sign() -> int:
    return randbits(1) and 1 or -1

HALF_PI: float = pi * .5
RADIUS_TEMPLATE: int = DIAMETER_TEMPLATE // 2
def encode_ellipse(self, idx: int, unserialized: bytes, results: list[str]) -> None:
    x, y = IDX_TO_XY[idx]
    bit_scale: int = len(unserialized) // 2
    rotation_plaintext: int = int.from_bytes(unserialized[:bit_scale])
    y_scale_plaintext: int = int.from_bytes(unserialized[bit_scale:])
    # Restrict to 90deg to avoid discontinuity of indistinguishable 0/180deg
    self.rotation = sample_uniform(rotation_plaintext, bit_scale, HALF_PI) * random_sign()
    # size = (e**rx_)*(e**ry_)*c = (rx=sqrt(c)*e**rx_)*(ry=sqrt(c)*e**-rx_) -> sample c and rx_
    sqrt_c: float = sqrt(MY_LOGNORM.ppf(sample_uniform(0, 0))) * RADIUS_TEMPLATE
    self.y_scale = float(MY_LOGNORM.ppf(sample_uniform(y_scale_plaintext, bit_scale, .5))) # .5: ry < rx
    rx: float = sqrt_c / self.y_scale
    ry: float = sqrt_c * self.y_scale
    # Noise
    x += MY_NORMAL.ppf(sample_uniform(0, 0))
    y += MY_NORMAL.ppf(sample_uniform(0, 0))
    assert self.decode(bit_scale) == unserialized
    results.append(f'  <ellipse cx="{x:.10g}" cy="{y:.10g}" rx="{rx:.10g}" ry="{ry:.10g}" style="transform:rotate({self.rotation:.10g}rad)"/>')
Ellipse.encode = encode_ellipse

def rotation_matrix_2d(radians: float) -> ndarray:
    s: float64 = sin(radians)
    c: float64 = cos(radians)
    return array(((c, s), (-s, c)))

def with_length(x: ndarray, length: float) -> ndarray:
    return x / l2_norm(x) * length

RIGHTWARD_STROKE_TEMPLATE: ndarray = array(((-1, -1), (1, 1))).T
LEFTWARD_STROKE_TEMPLATE: ndarray = array(((1, -1), (-1, 1))).T
ONE_DEGREE: float = pi / 180
HALF_DEGREE: float = pi / 360
def encode_cross(self, idx: int, unserialized: bytes, results: list[str]) -> None:
    x, y = IDX_TO_XY[idx]
    bit_scale: int = len(unserialized) // 3
    length_plaintext: int = int.from_bytes(unserialized[:bit_scale])
    delta_x_plaintext: int = int.from_bytes(unserialized[bit_scale:bit_scale * 2])
    delta_y_plaintext: int = int.from_bytes(unserialized[-bit_scale:])
    sqrt_c: float64 = sqrt(MY_LOGNORM.ppf(sample_uniform(0, 0)))
    leftward_length_scale: float64 = MY_LOGNORM.ppf(sample_uniform(length_plaintext, bit_scale))
    self.leftward_length = float((leftward_length_ratio := sqrt_c * leftward_length_scale) * DIAMETER_TEMPLATE)
    self.rightward_length = float((rightward_length_ratio := sqrt_c / leftward_length_scale) * DIAMETER_TEMPLATE)
    delta_x_normalized: float64 = MY_NORMAL.ppf(sample_uniform(delta_x_plaintext, bit_scale))
    delta_y_normalized: float64 = MY_NORMAL.ppf(sample_uniform(delta_y_plaintext, bit_scale))
    x += MY_NORMAL.ppf(sample_uniform(0, 0))
    y += MY_NORMAL.ppf(sample_uniform(0, 0))
    self.leftward_x_mean = delta_x_normalized * .5 * leftward_length_ratio + x
    self.rightward_x_mean = delta_x_normalized * -.5 * rightward_length_ratio + x
    self.leftward_y_mean = delta_y_normalized * .5 * leftward_length_ratio + y
    self.rightward_y_mean = delta_y_normalized * -.5 * rightward_length_ratio + y
    leftward_mean: ndarray = array((self.leftward_x_mean, self.leftward_y_mean))
    rightward_mean: ndarray = array((self.rightward_x_mean, self.rightward_y_mean))
    # Don't encode into rotation to avoid needing to truncate the Gaussian
    rightward_stroke: ndarray = (rotation_matrix_2d(sample_uniform(0, 0, ONE_DEGREE) - HALF_DEGREE) @ RIGHTWARD_STROKE_TEMPLATE).T
    leftward_stroke: ndarray = (rotation_matrix_2d(sample_uniform(0, 0, ONE_DEGREE) - HALF_DEGREE) @ LEFTWARD_STROKE_TEMPLATE).T
    rightward_start: ndarray = with_length(rightward_stroke[0], self.rightward_length * .5) + rightward_mean
    rightward_end: ndarray = with_length(rightward_stroke[1], self.rightward_length * .5) + rightward_mean
    leftward_start: ndarray = with_length(leftward_stroke[0], self.leftward_length * .5) + leftward_mean
    leftward_end: ndarray = with_length(leftward_stroke[1], self.leftward_length * .5) + leftward_mean
    assert self.decode(bit_scale) == unserialized
    results.append(f'  <line x1="{rightward_start[0]:.10g}" x2="{rightward_end[0]:.10g}" y1="{rightward_start[1]:.10g}" y2="{rightward_end[1]:.10g}"/>')
    results.append(f'  <line x1="{leftward_start[0]:.10g}" x2="{leftward_end[0]:.10g}" y1="{leftward_start[1]:.10g}" y2="{leftward_end[1]:.10g}"/>')
Cross.encode = encode_cross

def encode(unserialized: bytes, board: bytes) -> str:
    results: list[str] = [HEADER]
    state: list[Cell | None] = [None if c == b' ' else Ellipse(0, 0) if c == b'O' else Cross(0, 0, 0, 0, 0, 0, True) for c in unpack("9c", board)]
    bits_available_unscaled: int = sum(cell and cell.plaintext_bits or 0 for cell in state)
    bit_scale: int = (len(unserialized) + bits_available_unscaled - 1) // bits_available_unscaled
    # print(f"Encoding {bit_scale} bit(s) per variable")
    unserialized += urandom(bits_available_unscaled)
    offset: int = 0
    for idx, cell in enumerate(state):
        if not cell:
            continue
        length: int = cell.plaintext_bits * bit_scale
        cell.encode(idx, unserialized[offset:offset + length], results)
        offset += length
    results.append(FOOTER)
    return "\n".join(results)

def main():
    # key = 123
    # plaintext = b"TREASURE"
    # plaintext = "γεια".encode(CHARSET) # There was a noticeable ASCII-induced bias before implementing the key
    # board = b"O X OOXXX" # https://commons.wikimedia.org/wiki/File:Tic-tac-toe-game-1.svg
    # board = b"O X   X  "
    key: int = int(input("Key [0–255]: "))
    assert 0 <= key <= 255
    plaintext: bytes = input("What message would you like to encode? ").encode("ASCII")
    print("Each board row has 3 characters, each being an X, O, or space")
    board: bytes = "".join((
        input("Enter the 1st board row: "),
        input("Enter the 2nd board row: "),
        input("Enter the 3rd board row: "),
    )).encode(CHARSET)
    assert len(board) == 9 and board != b' ' * 9 and all(c == b' ' or c == b'X' or c == b'O' for c in unpack("9c", board))
    assert len(plaintext) == plaintext_length
    ciphertext: bytes = caesar_cipher(plaintext, (256 - key) & 255)
    while True:
        result: str = encode(ciphertext, board)
        try:
            assert caesar_cipher(decode(result), key) == plaintext
        except AssertionError:
            continue
        break
    # with open("generated.svg", "w") as f:
    #     f.write(result)
    print("Here is the message encoded in an SVG image:")
    print(result, end="")

if __name__ == "__main__":
    main()

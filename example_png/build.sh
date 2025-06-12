#!/bin/bash
set -e

for path in ../example_svg/*.svg; do
  out="$(basename "$path" .svg)".png
  google-chrome-stable --headless "$(realpath "$path")" --screenshot="$out" --window-size=1000,1000 --disable-gpu
  convert "$out" -crop 900x900+0+0 "$out"
done

convert +append LOOKLEFT.png xc:white[50x] SECRETED.png xc:white[50x] 'DIGHERE!.png' xc:white[50x] TOMORROW.png xc:white[50x] stitch.png
pngopt stitch.png
pngopt TREASURE.png
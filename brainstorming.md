# Brainstorming

This is my brainstorming of what probability distributions to use.

Warning: Many mistakes were fixed in the final Python.

## X
```
mx1=(x1s+x1e)/2
my1=(y1s+y1e)/2
mx2=(x2s+x2e)/2
my2=(y2s+y2e)/2
l1=math.sqrt((x1e-x1s)**2+(y1e-y1s)**2)
l2=math.sqrt((x2e-x2s)**2+(y2e-y2s)**2)
l1~exp(N(0,1)) <!--Modulate-->
l2~exp(N(0,1)) <!--Modulate-->
dx=mx2/l2-mx1/l1
dx~N(0,1) <!--Modulate-->
dy=my2/l1-my1/l1
dy~N(0,1) <!--Modulate-->
rotation1~N(0deg,1) <!--Random-->
rotation2~N(0deg,1) <!--Random-->
```

## O
```
<!--Avoid discontinuity at 180deg-->
rotation~U(0,360deg)===U(0,90deg) <!--Modulate-->

(rx*ry)~exp(N(0,1)) <!--Random-->
rx~exp(N(0,1))$ <!--Modulate-->
```

## Codec
### Encode
`scipy.stats.norm.ppf([plaintext,plaintext+1]/2**needed_bits)`
### Decode
`math.floor(scipy.stats.norm.cdf(ciphertext)*2**needed_bits)`

## SVG
https://css-tricks.com/grainy-gradients/

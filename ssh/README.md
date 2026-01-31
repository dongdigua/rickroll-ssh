# rickroll keys

These keys were left here intentionally

I run https://github.com/danielewood/vanityssh-go
and found this key with fingerprint

```
SHA256:EHmAwM3nwEexo/N85QHMjBjR1cKroLumPRFWkg0YekU rick@roll (ED25519)
                              ^^^^^^^
```

So users can see the rickroll fingerprint when first connecting

lets do a simple calculation using high school math:

say the regex is `r[1i]ckr[0o][1l]` and the SHA256 fingerprint's length is 44

then

$p=\dfrac{(44-7+1)\times2^4\times3^3\times64^{44-7}}{64^{44}}$

$q=1-p$

and the expectation of total try is

$E(x)=p\times\sum_{i=1}^{+\infty}i\times q^{i-1}$

$=p\times(\lim_{n \to +\infty}(\dfrac{n}{q-1}-\dfrac{1}{(q-1)^2})\times q^n+\dfrac{1}{(q-1)^2})$

$=\dfrac{1}{p}$

$\approx 267912190$

my machine is 1e+5 key/s

=> 2680s, acceptable

here's a table of different regexp

| regex                       |     estimated |
|:----------------------------|--------------:|
| `(?i)r[1i]ckr[0o][1l]`      |     267912190 |
| `(?i)r[1i]ckr[0o][1l]$`     |   10180663220 |
| `(?i)r[1i]ckr[0o][1l][1l]`  |    5869931946 |
| `(?i)r[1i]ckr[0o][1l][1l]$` |  217187482029 |
| `(?i)rickroll`              |   29716530480 |
| `(?i)rickroll$`             | 1099511627776 |
| `rickroll`                  | 7607431802990 |

so the current vanityssh-go is too slow
then it's another story https://github.com/dongdigua/vanityssh-cl

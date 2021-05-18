# julius-ancient-script - DCTF 2021

One of the easier crypto challenges of DCTF 2021 was "Julius' ancient script",
where we are given the ciphertext `rq7t{7vH_rFH_vI6_pHH1_qI67}` and the prompt

> I found this Ancient Roman papyrus. Could you decypher it for me?

which together with the name of the challenge very obviously demonstrates that
this is a Caesar cipher. The remaining information needed to decrypt this
ciphertext is the cipher's shift and the alphabet.

## Finding the shift

Since the flag starts with `dctf{` the cipher's shift is `+14` because
`d` has byte value 100 and `r` has byte value 114.

## Finding the alphabet

Simply using the classical alphabet (`a-z`) with the shift gives
`dc7f{7hT_dRT_hU6_bTT1_cU67}` which is not correct.
It is immediately apparent that the alphabet includes the digits
(`0-9`) so we can use the alphabet with both ranges concatenated
(`a-z0-9`). Note that the order of concatenation (`a-z0-9` or `0-9a-z`) does not matter
because the alphabet is circular and the shift is actually a rotation,
and in both cases `0` is immediately after `z` and `a` is immediately after `9`.
Using this alphabet gives the flag

```
dctf{th3_d13_h4s_b33n_c4st}
```

which is "The die has been cast" ("Alea iacta est"), a famous saying by
Julius Caesar when he crossed the Rubicon River
against the Senate of Rome, which matches the background information we were given
and the title of the challenge.

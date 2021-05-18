# a-simple-sp-box - DCTF 2021

One of the crypto challenges of DCTF 2021 was "A Simple SP Box!", where we have the prompt:

> It's just a simple SP-box, 150 tries should be enough for you.

and the connection command `nc dctf1-chall-sp-box.westeurope.azurecontainer.io 8888`.

## What is the SP box?

A [substitution-permutation network](https://en.wikipedia.org/wiki/Substitution%E2%80%93permutation_network)
is a type of block cipher which

> takes a block of the plaintext and the key as inputs,
> and applies several alternating "rounds" or "layers" of substitution boxes (S-boxes)
> and permutation boxes (P-boxes) to produce the ciphertext block.

and looks like this:

![SP network](https://upload.wikimedia.org/wikipedia/commons/c/cd/SubstitutionPermutationNetwork2.png)

so the SP box in this challenge is just one layer of such a network,
a substitution cipher stage followed by a permutation stage.
Some observations we can make about such a block cipher are:

- It is length-preserving: entering a message of a suitable size for the cipher results in
a ciphertext of the same size.
- The permutation stage is weak: using only one SP box by itself means the permutation is
just a simple scramble of the output of the substition stage.
- The substitution stage is weak: it is just a substitution cipher, which is easy to
break.

## Connecting to the server

Playing around with the server using netcat gives this dialogue:

```
$ nc dctf1-chall-sp-box.westeurope.azurecontainer.io 8888
Here's the flag, please decrypt it for me:
4q553iUUe5p'X15'5gXs54iiSXx's51g2q$%Xe4752
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
That doesn't look right, it encrypts to this:
HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
> 111111111111111111111111111111111111111111
That doesn't look right, it encrypts to this:
JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ
```

The server displays the ciphertext of the messages sent,
so this allows chosen-plaintext attacks on the SP box (with the caveat
that there is a limit of 150 attempts).
The choice of `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`
and `111111111111111111111111111111111111111111` are made because:

- The messages are the same length as the initial
ciphertext `4q553iUUe5p'X15'5gXs54iiSXx's51g2q$%Xe4752` (42 bytes)
so by the length-preserving property mentioned before,
we know 42 bytes is a suitable size for the cipher.
- Repeating the same symbol in the message makes the substition stage output
the corresponding repeated symbol as well.
- The repeated symbol output from the substitution stage is unchanged by
the permutation stage, because every permutation of a string with just one
symbol repeated is the string itself.

The dialogue shows that, for this particular session, the substitution stage
maps `A` to `H` and `1` to `J`. Effectively this repeated symbol
technique circumvents the permutation stage and probes just the substitution stage.
By doing this with all the symbols in the alphabet, the substitution stage's mapping
from input to output symbols can be obtained.

## Obtaining the alphabet

Before a repeating symbol message can be sent for each symbol in the alphabet,
it is necessary to determine the alphabet.
Since this is a text interface, the canonical first guess for the alphabet
is python's `string.printable`:

```python
# string.py
whitespace = ' \t\n\r\v\f'
ascii_lowercase = 'abcdefghijklmnopqrstuvwxyz'
ascii_uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
ascii_letters = ascii_lowercase + ascii_uppercase
digits = '0123456789'
punctuation = r"""!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""
printable = digits + ascii_letters + punctuation + whitespace
```

sending whitespace resulted in this error:

```
# Space
> A A
That doesn't look right, it encrypts to this:
Traceback (most recent call last):
  File "/ctf/sp_box.py", line 51, in <module>
    play()
  File "/ctf/sp_box.py", line 42, in play
    print(encrypt(guess))
  File "/ctf/sp_box.py", line 22, in encrypt
    message = [S_box[c] for c in message]
  File "/ctf/sp_box.py", line 22, in <listcomp>
    message = [S_box[c] for c in message]
KeyError: ' '
# Tab
> a     a
That doesn't look right, it encrypts to this:
Traceback (most recent call last):
  File "/ctf/sp_box.py", line 51, in <module>
    play()
  File "/ctf/sp_box.py", line 42, in play
    print(encrypt(guess))
  File "/ctf/sp_box.py", line 22, in encrypt
    message = [S_box[c] for c in message]
  File "/ctf/sp_box.py", line 22, in <listcomp>
    message = [S_box[c] for c in message]
KeyError: '\t'
```

and messages composed entirely of whitespace resulted in this error:

```
>  
Traceback (most recent call last):
  File "/ctf/sp_box.py", line 51, in <module>
    play()
  File "/ctf/sp_box.py", line 33, in play
    assert 0 < len(guess) <= 10000
AssertionError
```

so we know that the python string containing the input is stripped of whitespace and
whitespace is not in the alphabet. This left the set of symbols defined by:

```python
# Candidate alphabet
alphabet = string.digits + string.ascii_letters + string.punctuation
```

as the new candidate alphabet. However, when this was used, some punctuation symbols
resulted in similar errors:

```
# Tilde
> ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
That doesn't look right, it encrypts to this:
Traceback (most recent call last):
  File "/ctf/sp_box.py", line 51, in <module>
    play()
  File "/ctf/sp_box.py", line 42, in play
    print(encrypt(guess))
  File "/ctf/sp_box.py", line 22, in encrypt
    message = [S_box[c] for c in message]
  File "/ctf/sp_box.py", line 22, in <listcomp>
    message = [S_box[c] for c in message]
KeyError: '~'
# Backtick
> ``````````````````````````````````````````
That doesn't look right, it encrypts to this:
Traceback (most recent call last):
  File "/ctf/sp_box.py", line 51, in <module>
    play()
  File "/ctf/sp_box.py", line 42, in play
    print(encrypt(guess))
  File "/ctf/sp_box.py", line 22, in encrypt
    message = [S_box[c] for c in message]
  File "/ctf/sp_box.py", line 22, in <listcomp>
    message = [S_box[c] for c in message]
KeyError: '`'
```

so after removal of these excluded punctuation symbols the final alphabet was found to be:

```python
alphabet = string.digits + string.ascii_letters + r"""!"#$%'+.:;<=@_{}"""
```

which has size 78.

## Obtaining the substition mapping

The repeated symbol message procedure was done for each symbol in the alphabet to find the
substitution stage's mapping
using [the pwntools CTF library](https://github.com/Gallopsled/pwntools) (see full code in appendix):

```python
        enc = {}
        for c in alphabet:
            conn.recvuntil(b' ')
            msg = ''.join(repeat(c, msg_len))
            conn.sendline(msg)
            conn.recvline()
            enc[c] = conn.recvline(False)[0]
```

which consumes 78 (the alphabet size) out of the 150 attempts. These probing attempts
for the substitution stage look like the initial netcat exploration of the server,
but repeated over the whole alphabet:

```
[DEBUG] Sent 0x2b bytes:
    b'LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL\n'
[DEBUG] Received 0x5b bytes:
    b"That doesn't look right, it encrypts to this:\n"
    b'TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT\n'
    b'> '
[DEBUG] Sent 0x2b bytes:
    b'MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n'
[DEBUG] Received 0x5b bytes:
    b"That doesn't look right, it encrypts to this:\n"
    b'OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO\n'
    b'> '
[DEBUG] Sent 0x2b bytes:
    b'NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN\n'
[DEBUG] Received 0x5b bytes:
    b"That doesn't look right, it encrypts to this:\n"
    b'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\n'
```

where in this case it is found that `L` maps to `T`, `M` maps to `O`, and `N` maps to `e`.
Once the symbol mapping used by
the substitution cipher is found, the substitution stage is broken.

## Obtaining the permutation operation

To break the permutation stage, a message is sent composed of unique symbols and
the location of each corresponding substituted symbol in the ciphertext reveals
the permutation operation, which is a mapping from positions in the message to positions
in the ciphertext. In this case the first 42 (the message size) symbols of the alphabet
were used as the message:

```python
        msg = alphabet[:msg_len]
        sub = bytes(enc[c] for c in msg)
        conn.recvuntil(b' ')
        conn.sendline(msg)
        conn.recvline()
        res = conn.recvline(False)
        per = {sub.index(b): i for i, b in enumerate(res)}
```

this probing of the permutation stage only consumes one more attempt, for a total of 79 out of the limit
of 150 attempts spent on probing. The dialogue looks like this:

```
[DEBUG] Sent 0x2b bytes:
    b'0123456789abcdefghijklmnopqrstuvwxyzABCDEF\n'
[DEBUG] Received 0x5b bytes:
    b"That doesn't look right, it encrypts to this:\n"
    b'raM=$zPE2ZGm9NQ\'JpD67"_U4!.;LB:gYvFjoAbsC8\n'
```

where we can see the message is `0123456789abcdefghijklmnopqrstuvwxyzABCDEF` and the
positions of the corresponding substituted symbols in the ciphertext identify the permutation mapping,
which breaks the permutation stage.

## Decrypting the original ciphertext

The decryption process is simply inverting the permutation and then inverting the substitution.
Restore the substituted symbols back to their proper order and replace them with the original symbols:

```python
        dec = {b: c for c, b in enc.items()}
        conn.recvuntil(b' ')
        target_inv = ''.join(dec[target[per[i]]] for i in range(msg_len))
        conn.sendline(target_inv)
        print(conn.recvall())
```

which gives dialogue for the final (80th out of a limit of 150) attempt:

```
[DEBUG] Received 0x58 bytes:
    b"Here's the flag, please decrypt it for me:\n"
    b'gYqqy4!!JqZpEQqpq8E"qg44_ENp"qQ86YH=EJgfq6\n'
# 79 Probing attempts for substitution and permutation stages described previously
[DEBUG] Sent 0x2b bytes:
    b'dctf{S0_y0u_f0und_th3_cycl3s_in_th3_s_b0x}\n'
[x] Receiving all data
[x] Receiving all data: 0B
[DEBUG] Received 0x43 bytes:
    b'Well done. The flag is:\n'
    b'dctf{S0_y0u_f0und_th3_cycl3s_in_th3_s_b0x}\n'
[x] Receiving all data: 67B
[+] Receiving all data: Done (67B)
[*] Closed connection to dctf1-chall-sp-box.westeurope.azurecontainer.io port 8888
b'Well done. The flag is:\ndctf{S0_y0u_f0und_th3_cycl3s_in_th3_s_b0x}\n'
```

so the flag is `dctf{S0_y0u_f0und_th3_cycl3s_in_th3_s_b0x}`.

## Potential optimization

The repeated symbol message probing technique is not the most optimal
method for discovering the substitution cipher's mapping.
The permutation operation also has the property of cardinality preservation,
meaning the cardinality (number of occurrences) of a symbol in a string
is unchanged after the string is permuted.
By using this property, the substitution mapping can be found in less than
78 (alphabet size) probing attempts. Each probing attempt no longer contains a single repeated
symbol, but instead contains as many different symbols as possible, with the constraint
that the cardinalities of the symbols are unique and add to 42 (the message size).
Then each input symbol's corresponding substituted symbol can be identified as the substituted symbol
with the same cardinality as the input symbol. For example, one such probing message could
be `011222333344444555555666666677777777777777`, where
symbol *i* has cardinality *i+1* for *i=0,...,6* and symbol `7` has cardinality 14
instead of 8 because
the addition of a symbol `8` with cardinality 9 together with a cardinality 8 symbol `7` would
overflow the message size of 42. A dialogue with this message is:

```
> 011222333344444555555666666677777777777777
That doesn't look right, it encrypts to this:
5_"5Q"aE5_"5@"aL"_"5@"aL"_"5@"aQ"_"5@"aQ"a
```

where `0` maps to `E` (cardinality 1), `1` maps to `L` (cardinality 2), `2` maps to `Q` (cardinality 3),
and so on, ending with `7` mapping to `"` (cardinality 14).
So in this case with message size 42 each substitution mapping probing message can uncover the mapping
for at most eight symbols, and since the alphabet size is 78 the whole substitution mapping can be found
in ten probing messages. This means the attack could have taken only eleven probing attempts in total
to execute
(ten messages for the substitution stage, one for the permutation stage, and
not including the final successful flag message attempt).
However, the limit of 150 attempts for this challenge meant that this optimization was not
necessary.

## Appendix

The full code is:

```python
import string
from pwn import *
from itertools import *


def main():
    with context.local(log_level='debug'):
        conn = remote('dctf1-chall-sp-box.westeurope.azurecontainer.io', 8888)
        conn.recvline()
        target = conn.recvline(False)
        alphabet = string.digits + string.ascii_letters + r"""!"#$%'+.:;<=@_{}"""
        msg_len = len(target)
        enc = {}
        for c in alphabet:
            conn.recvuntil(b' ')
            msg = ''.join(repeat(c, msg_len))
            conn.sendline(msg)
            conn.recvline()
            enc[c] = conn.recvline(False)[0]
        msg = alphabet[:msg_len]
        sub = bytes(enc[c] for c in msg)
        conn.recvuntil(b' ')
        conn.sendline(msg)
        conn.recvline()
        res = conn.recvline(False)
        per = {sub.index(b): i for i, b in enumerate(res)}
        dec = {b: c for c, b in enc.items()}
        conn.recvuntil(b' ')
        target_inv = ''.join(dec[target[per[i]]] for i in range(msg_len))
        conn.sendline(target_inv)
        print(conn.recvall())


if __name__ == '__main__':
    main()
```

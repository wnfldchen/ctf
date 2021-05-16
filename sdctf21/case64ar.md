# case64ar - SDCTF 2021

One of the easier crypto challenges of SDCTF 2021 was "case64ar", where we are given the ciphertext `OoDVP4LtFm7lKnHk+JDrJo2jNZDROl/1HH77H5Xv` and the hint

> It is described as a blend of modern and ancient cryptographic techniques.

## Cipher identification

The name "case64ar" is a mix of "Caesar" and "base64", which suggests that this is a Caesar cipher on the base64 alphabet.
This is supported by the observation that the ciphertext symbols appear to be from the base64 alphabet and the hint,
where base64 is the modern technique and the Caesar cipher is the ancient technique.
The base64 alphabet is

```python
alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + '+/'
```

in python and has size 64. In base64, each symbol encodes a group of six bits, which can take any value from `000000` (0) to `111111` (63). The encoding table is

| Value Range | Symbol Range |
| -------- | -------- |
| 0-25 | A-Z |
| 26-51 | a-z |
| 52-61 | 0-9 |
| 62 | + |
| 63 | / |

with an additional padding character `=` which is not part of the alphabet.
The padding is needed when the message length is not a multiple of six bits long, which is often the case because messages are composed of whole numbers of eight bit wide bytes.
In this case, the ciphertext `OoDVP4LtFm7lKnHk+JDrJo2jNZDROl/1HH77H5Xv` is 40 symbols long, which corresponds to 240 bits or exactly 30 bytes,
so no padding is present (and indeed there are no `=` signs, which I presume would not be substituted in the ciphertext even if padding were necessary,
because it is not actually a part of the alphabet which the Caesar cipher rotates).
So we do not have to worry about padding in this case, and we can proceed with trying all 64 possible Caesar cipher shifts to the alphabet.

## Trying all possible Caesar shifts

To try all 64 possible shifts, we try adding the rotations `+0,+1,...,+62,+63` to the encoding table and check if the decoded result is something intelligible.
We can do this in python like so

```python
import itertools
import string


def grouper(iterable, n):
    args = [iter(iterable)] * n
    return itertools.zip_longest(*args, fillvalue=None)


def rotate(l, n):
    return l[n:] + l[:n]


def decode(s, n):
    alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + '+/'
    dictionary = {a: i for i, a in enumerate(rotate(alphabet, n))}
    bits = ''.join(format(dictionary[b], '06b') for b in s)
    return bytes(int(''.join(b), 2) for b in grouper(bits, 8))


def main():
    s = 'OoDVP4LtFm7lKnHk+JDrJo2jNZDROl/1HH77H5Xv'
    for d in range(64):
        output = decode(s, d)
        try:
            t = output.decode('ascii')
            if t.isprintable():
                print(t)
        except UnicodeDecodeError:
            pass


if __name__ == '__main__':
    main()
```

and we obtain as the only intelligible output the flag `sdctf{OBscUr1ty_a1nt_s3CURITy}`.

# safe-unix-playground - SDCTF 2021

One of the crypto challenges of SDCTF 2021 was "safe-unix-playground", where we are given the story:

> **$ safe-unix-playground # rm -rf /**
> Welcome to my awesome Unix command playground offered over a TCP port!
> With the free plan, you can run only example commands we provide.
> To run any other command, you will need to contact us for a premium partnership plan
> (Update 04/01/2020: premium plan cancelled due to COVID-19).

and the server code running at `nc unix.sdc.tf 1337` (see appendix).

## Interaction with the server

The first step is to figure out what the server code is doing.
There appear to be some whitelisted commands, where the whitelisting
is enforced by checking against the MD5 hashes of those commands:

```python
# Some nice sample commands, can be ran without the premium plan
whitelist_commands = ['ls', 'cat flag-1.txt']
hashes = list(map(lambda cmd: hashlib.md5(cmd.encode()).hexdigest(), whitelist_commands))
hashes2 = []
```

the empty list `hashes2` appears to be useless, but it appears to be a dynamic
whitelist of MD5 hashes which is added to and checked against in certain cases:

```python
def check(cmd):
    stripped = cmd.split(b'#',1)[0].strip()
    if hashlib.md5(stripped).hexdigest() in hashes:
        hashes2.append(hashlib.md5(cmd).hexdigest())
        try:
            return subprocess.check_output(stripped, shell=True)
        except:
            return
    elif hashlib.md5(cmd).hexdigest() in hashes2:
        try:
            return subprocess.check_output(stripped, shell=True)
        except:
            return
```

Going through the logic, the command is split at the first `#` symbol
and the prefix is stripped of whitespace.

1. In the first case, if this stripped prefix is in the
hardcoded `hashes` whitelist (so either `ls` or `cat flag-1.txt`)
then the hash of the entire original command is added to the dynamic `hashes2` whitelist
and the command is executed.
2. In the second case, if the hash of the entire original command
is in the dynamic `hashes2` whitelist then the command is executed.

A dialogue with the server confirms that if the prefix matches the hardcoded whitelist,
then the command is allowed:

```
$ nc unix.sdc.tf 1337
Welcome to the secure playground! Enter commands below
ls
flag-1.txt
flag-2.txt

cat flag-1.txt
ftcds{I_dare_y0u_subm1t_THIS!}

cat flag-2.txt
Invalid command with hash a0cc5350002ddbe21d656ec45c7763de

cat flag-1.txt # foo bar baz
ftcds{I_dare_y0u_subm1t_THIS!}
```

In other words, this is effectively a check which allows arbitrary `#` comments after the command.
Indeed, the heading of the story, "$ safe-unix-playground # rm -rf /", hints at the use of comments.
(And yes, the red herring flag was submitted and was wrong as expected - there was no Easter egg either.)

## The vulnerability

Clearly, the goal is to run a command with prefix:

```
cat flag-2.txt
```

since that is the file with the flag. Because we can whitelist hashes of commands with arbitrary comments
after the `#` as long as the prefix is either `ls` or `cat flag-1.txt`, we want to find such a command
(with some special comment) such that the hash of that command is the same as the hash of another command
with prefix `cat flag-2.txt` and some other special comment.
That is, a solution needs to be found for the equation:

1. `MD5('\s*ls\s*#[:any byte:]*')=MD5('\s*cat flag-2.txt\s*#[:any byte:]*')` or
2. `MD5('\s*cat flag-1.txt\s*#[:any byte:]*')=MD5('\s*cat flag-2.txt\s*#[:any byte:]*')`.

where `\s*` denotes any amount of whitespace and `[:any byte:]*` denotes any amount of arbitrary bytes.
In other words, this is
[a chosen-prefix collision attack](https://en.wikipedia.org/wiki/Collision_attack#Chosen-prefix_collision_attack).

## MD5 prefix collision attacks

Fortunately, much work has been done in
[collision attacks](https://github.com/corkami/collisions),
and in particular for [MD5 collision attacks using hashclash](https://github.com/cr-marcstevens/hashclash).
There are two types of collision attacks:

1. The identical-prefix collision attack:
given the same prefix, find two different suffixes such that both messages have the same hash.
This is more powerful than you first think,
because you can have an empty prefix and you can also control some bytes of the suffix.
3. The chosen-prefix collision attack:
given two prefixes, find two corresponding suffixes such that both messages have the same hash.
This takes a longer time than the identical-prefix collision attack,
so you want to try to do an identical-prefix collision, perhaps using an empty prefix
or controlling some bytes of the suffix.

Of the three MD5 prefix collision attacks covered in the first link of this section,
two are identical-prefix attacks (fastcoll and unicoll) and one is a chosen-prefix attack (hashclash).
Note that the hashclash software has a unicoll script (`poc_no.sh`) and a general
script for the chosen-prefix attack covered in the hashclash paper (`cpc.sh`).
Of these attacks, unicoll is the one which allows control over some bytes of the suffix and
has a predictable difference between the two suffixes:

1. The prefix is a multiple of 64 bytes and, of the suffix, you can control a small multiple of 4 bytes.
2. Byte 9 (the 10th byte if you start counting from 1) of the suffix is
incremented by one in the second message when compared to the first message.

Looking at the two messages that in this case must ultimately have the same hash:

```
Byte: 0123456789ABCDEF...
Msg1: cat flag-1.txt #...
Msg2: cat flag-2.txt #...
```

we can see that if we pick the layout with no leading whitespace and one space before the `#`,
then the length up to and including the `#` is a small multiple of 4 bytes (16 bytes) and
byte 9 of the second message (`0x32`) is indeed one greater than in the first message (`0x31`).
These are exactly the conditions which unicoll requires,
which means the chosen-prefix attack has just been converted into an identical-prefix attack,
which will save a lot of time. So we can go ahead with using
the `poc_no.sh` script from the hashclash software with an empty prefix and
a controlled first 16 bytes of the suffix `cat flag-1.txt #` (the first message will inherit this
template and the second message will have byte 9 incremented into `cat flag-2.txt #`).

## Running hashclash

Running `poc_no.sh` from the hashclash software as follows gives:

```
$ xxd prefix 
00000000: 6361 7420 666c 6167 2d31 2e74 7874 2023  cat flag-1.txt #
$ ../scripts/poc_no.sh prefix
# Output
$ md5sum collision{1,2}.bin
d122d69bfbda73ede5473c77bd3e9aa6  collision1.bin
d122d69bfbda73ede5473c77bd3e9aa6  collision2.bin
$ xxd collision1.bin 
00000000: 6361 7420 666c 6167 2d31 2e74 7874 2023  cat flag-1.txt #
00000010: 1a69 0a2a 05a1 4cb5 126c 437e ed01 6d82  .i.*..L..lC~..m.
00000020: 957d bfd6 2828 f538 e1e7 ead2 41a6 adf6  .}..((.8....A...
00000030: 5882 6479 14a3 4352 b320 0763 9510 d202  X.dy..CR. .c....
00000040: a6c8 0d03 75e4 d4ef 96aa 9667 c492 efc4  ....u......g....
00000050: fbba a8fc 6229 b670 392b ba25 7cf4 a6c4  ....b).p9+.%|...
00000060: a511 63d2 846d 5a64 f691 f5bd 3bf5 859e  ..c..mZd....;...
00000070: 6731 e0c5 6aa1 3a34 75d3 7f9b 96b1 9ca6  g1..j.:4u.......
$ xxd collision2.bin 
00000000: 6361 7420 666c 6167 2d32 2e74 7874 2023  cat flag-2.txt #
00000010: 1a69 0a2a 05a1 4cb5 126c 437e ed01 6d82  .i.*..L..lC~..m.
00000020: 957d bfd6 2828 f538 e1e7 ead2 41a6 adf6  .}..((.8....A...
00000030: 5882 6479 14a3 4352 b320 0763 9510 d202  X.dy..CR. .c....
00000040: a6c8 0d03 75e4 d4ef 96a9 9667 c492 efc4  ....u......g....
00000050: fbba a8fc 6229 b670 392b ba25 7cf4 a6c4  ....b).p9+.%|...
00000060: a511 63d2 846d 5a64 f691 f5bd 3bf5 859e  ..c..mZd....;...
00000070: 6731 e0c5 6aa1 3a34 75d3 7f9b 96b1 9ca6  g1..j.:4u.......
```

which are the two commands we desire.
The first command starts with `cat flag-1.txt #` and the second command
starts with `cat flag-2.txt #`, yet they both have the same hash of `d122d69bfbda73ede5473c77bd3e9aa6`
so sending the first command to the server should whitelist the second, allowing us to read
the flag. The only thing left is to figure out how to send the binary data after the `#` properly,
and for that the base64 command feature of the server can be used:

```python
    if data.strip() == BASE64_COMMAND:
        print('Enter command in base64> ', end='', flush=True)
        base64_command = sys.stdin.buffer.readline().strip()
        try:
            data = base64.b64decode(base64_command, validate=True)
```

which allows the transmission of the command to the server in base64 format, preserving the binary data.
Sending the base64 encoded commands gives the dialogue:

```
$ nc unix.sdc.tf 1337
Welcome to the secure playground! Enter commands below
b64
Enter command in base64> Y2F0IGZsYWctMS50eHQgIxppCioFoUy1EmxDfu0BbYKVfb/WKCj1OOHn6tJBpq32WIJkeRSjQ1KzIAdjlRDSAqbIDQN15NTvlqqWZ8SS78T7uqj8Yim2cDkruiV89KbEpRFj0oRtWmT2kfW9O/WFnmcx4MVqoTo0ddN/m5axnKY=
ftcds{I_dare_y0u_subm1t_THIS!}

b64
Enter command in base64> Y2F0IGZsYWctMi50eHQgIxppCioFoUy1EmxDfu0BbYKVfb/WKCj1OOHn6tJBpq32WIJkeRSjQ1KzIAdjlRDSAqbIDQN15NTvlqmWZ8SS78T7uqj8Yim2cDkruiV89KbEpRFj0oRtWmT2kfW9O/WFnmcx4MVqoTo0ddN/m5axnKY=
sdctf{MD5_iS_DeAd!L0ng_l1v3_MD5!}
```

and the flag `sdctf{MD5_iS_DeAd!L0ng_l1v3_MD5!}`.

## Notes on performance

Hashclash's unicoll implementation in `poc_no.sh` only took a few minutes to complete on
a consumer-grade computer. To get an idea of the comparative
performance of hashclash's generic chosen-prefix attack method on this task,
the `cpc.sh` script was also run on a 48-core server, which took 1.5 hours.

```
# Note that unlike with unicoll these chosen prefixes don't have a space before the "#"
$ xxd prefix1
00000000: 6361 7420 666c 6167 2d31 2e74 7874 23    cat flag-1.txt#
$ xxd prefix2
00000000: 6361 7420 666c 6167 2d32 2e74 7874 23    cat flag-2.txt#
$ ../scripts/cpc.sh prefix1 prefix2
# Output
$ md5sum prefix{1,2}.coll
80e921fef8d28ecccacb0fb8c4cbee25  prefix1.coll
80e921fef8d28ecccacb0fb8c4cbee25  prefix2.coll
# In fact, it was run twice, in parallel on two servers, to better gauge running time
# This is the second pair of messages, both pairs successfully unlocked the flag
$ md5sum prefix{1,2}.coll
0e51644041a5082dd9d9070e5a849ab1  prefix1.coll
0e51644041a5082dd9d9070e5a849ab1  prefix2.coll
```

While this means it may be feasible to run the generic chosen-prefix attack
overnight on a consumer-grade 8-core or 6-core computer if one did not realize
that the unicoll identical-prefix attack was possible rather than the generic chosen-prefix attack,
the unicoll identical-prefix attack is definitely the better solution in the time-limited context
of a CTF competition. See the appendix for both pairs of commands which were generated using this
slower alternative method.

## Appendix

The full server code given is:

```python
import subprocess
import hashlib
import base64
import sys
import binascii

ERROR = "Invalid command with hash "
BASE64_COMMAND = b'b64'

# Some nice sample commands, can be ran without the premium plan
whitelist_commands = ['ls', 'cat flag-1.txt']
hashes = list(map(lambda cmd: hashlib.md5(cmd.encode()).hexdigest(), whitelist_commands))
hashes2 = []

def check(cmd):
    stripped = cmd.split(b'#',1)[0].strip()
    if hashlib.md5(stripped).hexdigest() in hashes:
        hashes2.append(hashlib.md5(cmd).hexdigest())
        try:
            return subprocess.check_output(stripped, shell=True)
        except:
            return
    elif hashlib.md5(cmd).hexdigest() in hashes2:
        try:
            return subprocess.check_output(stripped, shell=True)
        except:
            return

print("Welcome to the secure playground! Enter commands below")
while True:
    sys.stdout.flush()
    data = sys.stdin.buffer.readline()
    if data == b'': # EOF
        sys.exit()
    if data.strip() == BASE64_COMMAND:
        print('Enter command in base64> ', end='', flush=True)
        base64_command = sys.stdin.buffer.readline().strip()
        try:
            data = base64.b64decode(base64_command, validate=True)
        except binascii.Error as e:
            print('ERROR: Invalid base64: {}'.format(e))
            continue
    result = check(data)
    if result:
        print(result.decode())
    else:
        print(ERROR + hashlib.md5(data).hexdigest() + "\n")
```

The first pair of commands generated by the slower
alternative hashclash generic chosen-prefix attack method instead of unicoll:

```
$ base64 -w 0 prefix1.coll 
Y2F0IGZsYWctMS50eHQjPWKEEQF1003rgJPeMcHZMEX7vh5x8ApjdagwqpgXyuOia449RAAAAAC1kVOZRWsis+MeRTcEk3WNpEQAzX9S2A6zlCUiEBDg5m0qlFHeTUyfdSvSceoGGvM+kX2kMCB2FXgjsIHZdkjp0DttTBn9XJU0w+8R2goitUodTxIr21ECwnLb4GgE5ipAgjrZLuR2LOk0X6y+b9sIabp9YddufKDanUwcPwofnJjwDcMxuwijrl6sZdEeiY0iJgEkoj9+w5v7xBwUb2t6dD3Tg7qLbaq1wKz843tN/JcqaswqEsz3G6Evrfu1Jkh5z4jmagedlRwDyb8UN8Y3LOgDYe4S41LjnRfJCdhZsYiFc2IgWMUxD1a4sTHhz6DegM6LbImPI1CdPD/d0ADzmbxRXYwWL2M3LOori0sb4K0dx81h0WWXMMPZ7mlkFWtRdmCry/b+TqHIEVSqea/pRD7R2P/0Ie1w19sF6z+lKc/ezyF2cLd4sSf0c+74UtrhuhoIPF45eCEfTDQdBsxXV8QZ1rHQkFOCfTy5u4yggZKA3j/r7xHkFUPlbWbwVBZ3UIG8artWVJh0wCJ1xEwBuynxhOfEP/EbuSN99KibhSpJdUcduTUzUSSi2Jiit3DptRakPRsOzowhdo1Oih843uF0hEK2Grk=
$ base64 -w 0 prefix2.coll 
Y2F0IGZsYWctMi50eHQjKBrTUmLLx1XXzYblX9CDAZtNVQZhq4gRivpNNLN1WUZWl+9sSgAAAAAxl/f/3E7PMeMeRTcEk3WNpEQAzX9S2A6zlCUiEBDg5m0qlFHeTUyfdSvSceoGGvM+kX2kLiB2FXgjsIHZdkjp0DttTBn9XJU0w+8R2goitUodTxIr21ECwnLb4GgE5ipAgjrZLuR2LOk0X6y+b9sIabp9YdeufKDanUwcPwofnJjwDcMxuwijrl6sZdEeiY0iJgEkoj9+w5v7xBwUb2t6dD3Tg7qLbaq1wKz843tN/JcqaswqEsznG6Evrfu1Jkh5z4jmagedlRwDyb8UN8Y3LOgDYe4S41LjnRfJCdhZsYiFc2IgWMUxD1a4sTHhz6DegM6LbImHI1CdPD/d0ADzmbxRXYwWL2M3LOori0sb4K0dx81h0WWXMMPZ7mlkFWtRdmCry/b+TqHIEVSqea/pRD7R2P/0Ielw19sF6z+lKc/ezyF2cLd4sSf0c+74UtrhuhoIPF45eCEfTDQdBsxXV8QZ1rHQkFOCfTy5u4yggZKA3j/r7xDkFUPlbWbwVBZ3UIG8artWVJh0wCJ1xEwBuynxhOfEP/EbuSN99KibhSpJdUcduTUzUSSi2Jiit3DptRak/RoOzowhdo1Oih843uF0hEK2Grk=
```

The second pair of commands:

```
$ base64 -w 0 prefix1.coll 
Y2F0IGZsYWctMS50eHQjPWKEEQF1003rgJPeMcHZMEX7vh5x8ApjdagwqpgXyuOia449RAAAAAB4g6VOELbl27PYjcuVPoHkIr6Ev1aqe8F+lBIblpBXRLp1QGG8r1W8GWUU5ESpcvz73vTZ+2zFgnkyzJCkf38cFPjOix1IOhfVqqBga9kcO8sPzI4HEirjUFHD85EQSQl9K+alYwAK1nwPaqFKTu5B0NZtO2fY/ylnoQLz/HGdourBuU7DX7pNR+MAp4WdFbIqc6fzIaiTHjrzkVS5UG6Kr029DBe0r/VL/zx7gt9DzOFxetPVOBUKTNi0ZpDTg4I5uUYJWb6Fg1SNvKCl8zCe/Nx/bM9DShDIherPSlCf9Ptc3zPVTV7mH+2KC1eyF5RhWAeAL7Beb6hnXR/RteRQX2pdgAw2QBtz2aXnRvT0q+6U26gHPqnOURnyLiYv9KXpMKYmlPioEHVvhXH+MiSM1O2obn6xPMp6tXpvaXehtOAmHHL8eVMmJzZrEP/Z8DpyoeZsJdCesWMM7aDSSGljANH9PE0q+JwxzWLWQFLqHUFQO3rJf/iymiZi1KWPTucncwmQLFCjtNbYVofpI+fm+dmMcw7WtymOeoH7eyVEULcMWKaAfWYrF3StCjV8x/o6mFi/0QPx//YQlmtEOg04km3La8O4CSA=
$ base64 -w 0 prefix2.coll 
Y2F0IGZsYWctMi50eHQjKBrTUmLLx1XXzYblX9CDAZtNVQZhq4gRivpNNLN1WUZWl+9sSgAAAADLfge8wR8ELbPYjcuVPoHkIr6Ev1aqe8F+lBIblpBXRLp1QGG8r1W8GWUU5ESpcvz73vTZ+2zFhHkyzJCkf38cFPjOix1IOhfVqqBga9kcO8sPzI4HEirjUFHD85EQSQl9K+alYwAK1nwPaqFKTu5B0NZtO2fY7ylnoQLz/HGdourBuU7DX7pNR+MAp4WdFbIqc6fzIaiTHjrzkVS5UG6Kr029DBe0r/VL/zx7gt9DzOFxetPVOBUCTNi0ZpDTg4I5uUYJWb6Fg1SNvKCl8zCe/Nx/bM9DShDIherPSlCf9Ptc3zPVTV7mH+2KC1eyF5RhWAeAL/Beb6hnXR/RteRQX2pdgAw2QBtz2aXnRvT0q+6U26gHPqnOURnyLiYv9KXpMKYmlPioEHVvhXH+MiSM1O2obn61PMp6tXpvaXehtOAmHHL8eVMmJzZrEP/Z8DpyoeZsJdCesWMM7aDSSGljANH9PE0q+JwxzWLWQFLqHUFQO3pJf/iymiZi1KWPTucncwmQLFCjtNbYVofpI+fm+dmMcw7WtymOeoH7eyVEULcMWKaAfWYrF3StCjV8x/o6mFi/0gPx//YQlmtEOg04km3La8O4CSA=
```

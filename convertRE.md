# convertRE #

convertRE.py is a shell-oriented tool for easy conversion of arbitrary input in terms of simple manipulation strategies. This includes XOR, ROL, ROT, as well as wrappers for BASE(16, 32, 64) encoding and others.

## Usage ##

```
<pre>

./convertre.py 
Usage: convertre.py [options]

Options:
  -h, --help            show this help message and exit
  -v, --version         show disclaimer

  I/O options:
    these parameters control the input source.

    -s INPUT_STRING, --input-string=INPUT_STRING
                        input string to manipulate
    -i INPUT_FILE, --input-file=INPUT_FILE
                        input file to load and manipulate
    -p, --input-pipe    receive input from pipe
    -o OUTPUT_DEST, --output-destination=OUTPUT_DEST
                        this option allows definition of an output folder
                        where manipulation results will be stored.

  MANIPULATION options:
    these parameters control the type of manipulation.

    -c CAESAR, --caesar=CAESAR
                        apply caesar-style byte-wise rotation by ROT=[0-25]
                        positions in the alphabet
    -d DECODER, --decoder=DECODER
                        decode with specified method: (BASE32, BASE64, BASE16,
                        DEFLATE, DECOMPRESS, BASE32HEX)
    -e ENCODER, --encoder=ENCODER
                        encode with specified method: (BASE32, BASE16, BASE64,
                        COMPRESS, BASE32HEX, INFLATE)
    -f FIND, --find=FIND
                        find occurences of a target in the search space
                        created by all possible XOR, ROL, ROT and CAESAR
                        operations against the input.
    -l ROL, --rol=ROL   apply byte-wise bitrotation by ROL=[0-7] bits
    -r ROT, --rotate=ROT
                        apply byte-wise linear shift left by ROT=[0-255]
                        positions in ASCII range.
    -x XOR, --xor=XOR   apply byte-wise XOR operation with given (multi-byte)
                        string XOR. It is possible to specify arbitrary bytes
                        with usual string-escaping: "\x41\x20\x42" equals 
                        "A B". Will spit errors if XOR stings ends on a single
                        backslash
    -y REVERSE, --reverse=REVERSE
                        reverse input, ordered in blocks of size
                        REVERSE=[0..len(input)].


</pre>
```

## Examples ##
converting to hex:
```
$ ./convertre.py -s "ABCDEFGH" -e base16 | less
4142434445464748
```
decoding base64:
```
$ ./convertre.py -s "QUJDREVGR0g=" -d base64 | less
ABCDEFGH
```
historic issues:
```
$ ./convertre.py -s "Caesar would know" -c 3 | less
Fdhvdu zrxog nqrz
```
byte-order conversion:
```
$ ./convertre.py -s "00401bad" -y 2 | less
ad1b4000
```
piping input from shell (-p option) and XOR'ing with " ":
```
$ echo -ne "M\x41K\x45L\x4FW\x45R" | ./convertre.py -p -x "\x20"
makelower
```
Searching for simply obfuscated strings (similar to [XORSearch by Didier Stevens](http://blog.didierstevens.com/programs/xorsearch/)) in an old spybot sample (-i for file-input):
```
$ ./convertre.py -i spybot.exe -f "CurrentVersion" | less
-> XOR completed
-> ROL completed
-> ROT completed
-> CAESAR completed.
finished, generating output.
Multi-Find Results: 2 total occurrences (XOR: 0, ROL: 0, ROT: 2, CAESAR: 0)
     ROT(033) 0x0000893b: �B: �SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce�SOFTWARE\
     ROT(033) 0x0000896d: Once�SOFTWARE\Microsoft\Windows\CurrentVersion\Run�������������
```
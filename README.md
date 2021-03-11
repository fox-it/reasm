# reasm
Extract algorithms of the malware and re-compile it on linux for decrypting stuff using same malware algorithms.

There are algorithms in the malwre complex to implement in python and they are changing all the time the algorithm so why no executing their asm instead implementing it in python?

This is useful for decrypting and encrypting stuff, decompressing and so on.

This tool extract the asm and prepare it to be compilable on a out.asm file, and also prepare the c file to call the asm algorithm.

Powered by Radare.

### Usage
    python3 reasm.py [binary name] [start address] [end address]

    example:
        python3 reasm.py malware_dump.bin 0x04f6bb50 0x0x04f6bc76


### Pics

For example formbook use standard algorithms but modified:

![rc4 modified](pics/fb_rc4.png)
![b64](pics/fb_b64.png)
![main](pics/fb_main.png)
![encrypted](pics/fb_encrypted.png)


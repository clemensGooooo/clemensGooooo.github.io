---
title: Count On Me - Midnight Flag CTF - Walkthrough
date: 2025-04-13 11:00:00 +0200
categories: [Midnight Flag CTF]
tags: [crypto, aes,padding_oracle]
description: Use a AES-CRT padding oracle vulnerability to extract the flag.
image:
  path: /assets/blog/Sublocku/logo.png
  alt: Midnight Flag CTF logo
---

## Description

This is a Write-Up to another challenge of the amazing Midnight Flag CTF. The challenge is named "Count on Me" and is in the Crypto category.

## Code analysis

Provided code:

```py
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import bytes_to_long
import os

class CTR:
    def __init__(self):
        self.key = os.urandom(16)

    def encrypt(self, pt):
        iv = os.urandom(16)
        ctr = Counter.new(128, initial_value=bytes_to_long(iv))
        cipher = AES.new(self.key, AES.MODE_CTR, counter=ctr)
        enc = iv + cipher.encrypt(pad(pt, 16))
        return enc

    def decrypt(self, ct):
        try:
            ctr = Counter.new(128, initial_value=bytes_to_long(ct[:16]))
            cipher = AES.new(self.key, AES.MODE_CTR, counter=ctr)
            dec = unpad(cipher.decrypt(ct[16:]), 16)
            return dec
        except Exception:
            return False

if __name__ == "__main__":
    cipher = CTR()
    flag = os.getenv('FLAG', 'MCTF{ThisIsAFakeFlag}').encode()
    ct = cipher.encrypt(flag)
    print(f"CTR(flag)={ct.hex()}")
    while 1:
        enc = bytes.fromhex(input("enc="))
        dec = cipher.decrypt(enc)
        if bool(dec) or dec == flag:
            print('Look\'s good')
        else:
            print('Hum,this is a weird input')
```

We have a relatively short piece of code to analyze. First, the flag is encrypted using AES in CTR (Counter) mode. You can read more about CTR mode [here](https://de.wikipedia.org/wiki/Counter_Mode). CTR mode works by taking a nonce and a key to encrypt a counter value. The result is then XORed with the plaintext to produce the ciphertext.

![](/assets/blog/Count%20On%20Me/AES-CRT.png)

From Wikipedia.

After we get the encrypted flag send, we can decrypt as much as we want, but we don't get the output, we only get to know if whether the decryption was successful or not. If it was successful we get `print('Look\'s good')`, if not we get `print('Hum,this is a weird input')`.

## Vulnerability

You may notice that the data is padded before encryption and then unpadded after the decryption. The `unpad()` raises an error if the padding is incorrect. So, if the padding is invalid, the program prints `'Hum, this is a weird input'`. This behavior can actually help us to extract the flag by exploiting the program through a padding oracle attack.

## The attack

At a high level, the idea of this attack is to try every possible byte for the last byte of a block.  Since we have a padding oracle, it will tell us whether the padding is valid or not. We can iterate through all possible byte values until we find one that results in valid padding (`0x01` for the last byte) we can now do some magic XORing to get the original byte from the information we found. You can repeat this now for every byte and this way extract the data. 

After successfully decrypting one block, we can remove it and continue with the next. Since padding is only applied to the last block and has a maximum length of 16 bytes (for AES), we need to cut if off and start again with padding of 0x01 for the next block.

Normally I do padding oracle attacks only on CBC but they also work on CRT.

More info to padding oracles:
- [TryHackMe Challenge](/posts/Decryptify/#padding-oracle) and [TryHackMe Room](https://tryhackme.com/room/paddingoracles) (Only for subscribers)
- [Article](https://www.linkedin.com/pulse/oracle-padding-attack-mahmoud-jadaan-k9ebe)

## Final script


Note: Padding oracle attacks are sometimes a little bit unstable because of the amount of data send and the sometimes weird behaviors, this is why I added so many prints which fill up the terminal, just for debugging.

```py
from pwn import *
import json

p = remote("chall4.midnightflag.fr",14984)

def split_into_blocks(data, block_size=16):
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]

def get_ciphertext():
    ciphertext = p.recvline_startswith(b"CTR(flag)=").split(b"CTR(flag)=")[1]
    ct = ciphertext.decode()
    return ct

def check_padding(ct):
    get_c = ct.hex()
    p.sendlineafter(b"enc=",get_c)
    ciphertext = p.recvline()
    if b"Look" in ciphertext:
        return True
    else:
        return False

def find_chr(before,after,ori):
    for i in range(256):
        send_ct = before+i.to_bytes(1)+after
        print(f"Trying: {send_ct.hex()}")
        res = check_padding(send_ct)
        if res == True:
            return i
    assert Exception("No valid padding found")


def find_padding(before,block):
    known = b""
    padding = []
    for i in range(1,17,1):
        modified_block = block[:16-i] 
        new_bef = before+modified_block
        after_new = bytes([(padding[v-1]^i) for v in range(len(padding),0,-1)])
        
        res = find_chr(new_bef,after_new,block[16-i])
        known += (res^i^block[16-i]).to_bytes(1)
        padding.append(i^res)
        print(f"Found bytes: {bytes(known[::-1])}")
    return known[::-1]
    

ct = get_ciphertext()
print(f"Ciphertext: {ct}")

ct = bytes.fromhex(ct)

print("Starting....")
blocks = split_into_blocks(ct)

final = ""

part1 = find_padding(b"".join(blocks[:2]),blocks[2])
part2 = find_padding(b"".join(blocks[:1]),blocks[1])
final = part2+part1

print("..... finished!")
print(f"Found: {final}")

p.interactive()
```

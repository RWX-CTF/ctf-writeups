#!/usr/bin/env python3
# *.* coding: utf-8 *.*

import random
import struct

'''
Challenge superseed - Hack The Box - CTF
'''

def solve(seed, cipher):
    random.seed(seed)

    plain = ''
    for c in cipher:
        plain += chr(ord(c) - random.randrange(512))

    print(plain)


def bruteforce(cipher):
    # Subtract each character from 'HTB{' from the ciphertext to get the
    # key's first four numbers.
    key = [ ord(cipher[i]) - ord(c) for i, c in enumerate('HTB{') ]

    try:
        for i in range(0, 0xffffff):
            print(f'\x1b[K[*] guess : {hex(i)}', end='\r')
            random.seed(struct.pack('<I', i)[:3])

            for k in key:
                if k != random.randrange(512):
                    break

            else:
                print(f'\x1b[K[+] FOUND: {hex(i)}')
                return i

        else:
            print('\x1b[K[-] NOT FOUND :(')
    except KeyboardInterrupt:
        print('\x1b[K[!] INTERRUPTED')

    return None

if __name__ == '__main__':

    cipher = ['ű', 'Ƚ', 'Ƴ', 'ǿ', 'ɞ', 'ǔ', 'ɣ', '\x96', 'ū', 'ó', 'b', 'Ƚ']
    seed = bruteforce(cipher)

    if seed is not None:
        solve(struct.pack('<I', seed)[:3], cipher)


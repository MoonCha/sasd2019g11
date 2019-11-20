#!/bin/sh
nasm -f bin -o empty.elf empty.asm
nasm -f bin -o simple.elf simple.asm
nasm -f bin -o symtab.elf symtab.asm

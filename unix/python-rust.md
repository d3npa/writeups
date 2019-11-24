# Rust + Python 連携 (メモ)

#### 目的：PythonからRustの関数を呼び出して、返し値をPython側で処理する。<br><br>

先ずRustライブラリを作成する。(ファイル名: lib_d3npa_ffi.rs)
```
#![crate_name = "_d3npa_ffi"] // 頭に「lib」が付けられる
#![crate_type = "cdylib"]

#[no_mangle]
pub extern "C" fn add(x: i32, y: i32) -> i32 {
    return x + y;
}
```

`extern "C"`を使ったことで関数がC言語から呼び出せられる形にコンパイルされて、`#[no_mangle]`の属性はコンパイラーへ「この関数の名前を変えずにそのままにしておいて」と言うサインです。さてコンパイルしましょう。

```
$ rustc lib_d3npa.rs
$ ls -l *.so
-rw-------  1 d3npa  users  2348224 Aug 21 12:33 lib_d3npa.so
```

なうライブラリを利用するPythonコードを書きましょう！(ファイル名: lib_d3npa.py)
```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from cffi import FFI

ffi = FFI()
ffi.cdef("""
    int add(int x, int y);
""")
lib = ffi.dlopen("./lib_d3npa_ffi.so")

def add(x, y):
    return lib.add(x, y)
```
`cffi`とはpipからインストールできるC言語連携モジュールです。`cdef()`の引数に使いたい関数のシグニチャーを宣言する。最後に`lib`をハンドルとし、`ffi.dlopen()`でライブラリを読み込みます。以下のよう、`lib.add(x, y)`というかたちでRustライブラリの関数を呼び出すことができます。

最後は (ファイル名: main.py)
```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import lib_d3npa

def main():
    x, y = 10, 32
    print("{} + {} = {}".format(x, y, lib_d3npa.add(x, y)))

if __name__ == "__main__":
    main()
```

いざ実行！
```
$ ls -1
lib_d3npa.py
lib_d3npa_ffi.rs
lib_d3npa_ffi.so
main.py
$ python3 main.py
10 + 32 = 42
```


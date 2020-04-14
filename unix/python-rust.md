# PythonからRust関数を呼び出す方法

#### はじめに
Python言語の内部にはC言語で作られている部分がありますが、C言語関数をPythonの中から呼び出すために、CFFI（英: C Foreign Function Interface）というモジュールが使われるらしいです。なおRust言語でライブラリを作るときは、C関数としてエクスポートすることが可能なので、Rustの関数もPythonから呼び出すことができるわけです。

今回はPython 3の中からrust言語でコンパイルした関数を呼び出す方法を紹介したいと思います。

#### 準備
Python3とRustがインストールされていることを確認してください。
更に、環境によって、`cffi`をpipからインストールする必要があるかもしれないので、ご注意ください。

#### Rust関数作成
例のため、`cargo`を使わずにしましたが、crateの設定を変えると同じことができます。
```rust
#![crate_type = "cdylib"]

#[no_mangle]
pub extern "C" fn add(x: i32, y: i32) -> i32 {
	return x + y;
}
```
crate_type、つまりクレートの種類をC言語の動的ライブラリに設定。続いて整数2つを和を返す関数`add`を実装します。なお関数の上に`#[no_mangle]`という文を付けましたが、付けないままにコンパイルしてしまうと、関数名がランダム化されてしまうのです。Pythonから関数を呼び出そうとするときに関数名がわからないと困りますので、エクスポートしたい関数に必ず`#[no_mangle]`を付けておきましょうね。

```
$ ls
example.rs
$ rustc example.rs
$ ls -1
example.rs
libexample.so
```
こうして`libexample.so`が作られました。

#### Pythonコード作成
次にPythonコードを書いていきます。
```python
#!/usr/bin/env python3
import cffi

ffi = cffi.FFI()
ffi.cdef('''
	int add(int x, int y);
''')
lib = ffi.dlopen('./libexample.so')

print(lib.add(5, 7))
```
ザッと言葉にすると、`ffi`オブジェクトを宣言し、ライブラリをインポートする前に`cdef`でインポートしたいC関数を定義しておきます。それから`dlopen`でライブラリを読み取り、libと名付けてpythonモジュールのように使います。

```
$ python3 example.py
12
```

# FreeBSDカーネルモジュール開発環境の構築

最近「[Designing BSD Rootkits](https://www.amazon.co.jp/Designing-BSD-Rootkits-Introduction-Hacking-ebook/dp/B002MZAR6I)」という本を読んでいました。ついでにこの本をカーネルハッキングに興味を持ってる方におすすめします。なお、環境がFreeBSDになっているのですが、私が勉強のために使っている環境の構築手順を解説していきます。

## バーチャルマシン（vagrant）
仮想環境を管理するために vagrant というツールを使ってるんですが、これは任意です。以下 `Vagrantfile` になります。
```
Vagrant.configure("2") do |config|
  config.vm.box = "generic/freebsd12"
  config.vm.synced_folder "proj/", "/home/vagrant/proj"
end
```
- `generic/freebsd12` というイメージを使用する
- ホスト上の `./proj/` というフォルダをVMの `/home/vagrant/proj` に同期する

それから `vagrant up` を打つと vagrant がVMをダウンロードして起動してくれます。なお、FreeBSDのイメージでは共有フォルダが使えないので、rsyncが自動的にインストールされましたが、VMに接続する前に `vagrant rsync-auto &` を実行しないと共有フォルダが同期されませんので忘れないようにしましょう！最後に `vagrant ssh` でVMに接続することができます。FreeBSDへようこそ！

## rsync によるファイル同期の注意点
ホスト側でファイルに変更が合ったとき、共有フォルダ全体がVMに自動的にコピーされます。しかし、変更はVMの方で行われた場合、ホストには反映されません。一方同期ってイメージです。さらに、一回VMで新しいファイルを作成して、今度ホストのフォルダが同期されるとき、新しいファイルが消えてしまいます。なので注意が必要です。

## パッケージミラーの設定
デフォルト設定ではアメリカのサーバーがパッケージミラーになっています。日本から使うと非常に遅いので、日本のサーバーに変えます。ミラーを設定するには、`/etc/pkg/FreeBSD.conf` というファイルを編集します。こちらは公式ミラーの一覧です：[FreeBSD FTP Sitesページ](https://www.freebsd.org/doc/handbook/mirrors-ftp.html#mirrors-jp-ftp)

```
FreeBSD: {
  url: "pkg+ftp://ftp4.jp.FreeBSD.org/${ABI}/quarterly", # <- ここ変えたよ
  mirror_type: "srv",
  signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg",
  enabled: yes
}
```

編集が終わったら `pkg update` でレポジトリキャッシュを更新します。

## カーネルのソースファイルを入手
さっきのFTPミラーから、OSの全てのソースコードを[ダウンロードすることができます](ftp://ftp4.jp.freebsd.org/pub/FreeBSD/releases/amd64/amd64/12.1-RELEASE/)。

```
ftp ftp://ftp4.jp.freebsd.org/pub/FreeBSD/releases/amd64/amd64/12.1-RELEASE/src.txz
```

※ `tar Jtf src.txz` で、アーカイブを解凍せずに中身を確認することができます。

```
# tar Jtf /root/src.txz | head
usr/src/
usr/src/libexec/
usr/src/sys/
usr/src/LOCKS
usr/src/stand/
usr/src/.gitattributes
usr/src/UPDATING
usr/src/Makefile
usr/src/crypto/
[ 省略... ]
```
`/` フォルダにて解凍コマンドを実行すると、ソースコードは `/usr/src` 以下に置いてくれます。

```
cd /
tar Jxvf /root/src.txz
```

## Hello Worldカーネルモジュール

> **注意：** <br>
> `proj/` 以下の開発・ファイル編集など、必ずホストにて行うように気をつけましょう。<br>
> 詳しくは上記の[ファイル同期の注意点](#ファイル同期の注意点)を確認してください。

開発はホストでやります。

### proj/chapter01/helloworld/hello.c
```c
#include <sys/param.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/kernel.h>

static int load(struct module *module, int cmd, void *args) {
	int error = 0;
	switch(cmd) {
	case MOD_LOAD:
		uprintf("Hello, world!");
		break;
	case MOD_UNLOAD:
		uprintf("Goodbye, cruel world...\n");
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}
	return error;
}

static moduledata_t hello_mod = { "hello", load, NULL };
DECLARE_MODULE(hello, hello_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
```

### proj/chapter01/helloworld/Makefile
```
KMOD = hello
SRCS = hello.c

.include <bsd.kmod.mk>
```

ただしコンパイルはVMの方で行います。
```
$ cd ~/proj/chapter01/helloworld
$ make
[省略...]
$ sudo kldload ./hello.ko
Hello, world!
$ sudo kldunload ./hello.ko
Goodbye, cruel world...
$
```

ソースが変わる際、rsync がフォルダを上書きし、コンパイル結果が消され綺麗な状況に戻ります。
```
$ ==> default: Rsyncing folder: 省略/proj/ => /home/vagrant/proj
$ ls
Makefile    hello.c
$
```

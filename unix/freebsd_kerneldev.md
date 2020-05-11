# FreeBSDカーネルモジュール開発環境の構築

最近「[Designing BSD Rootkits](https://www.amazon.co.jp/Designing-BSD-Rootkits-Introduction-Hacking-ebook/dp/B002MZAR6I)」という本を読んでいました。本は英語ですが、カーネルハッキングに興味を持った方に強くオススメします。なお、メインOSとして私はLinux使っているのですが、環境がFreeBSDになっているので、仮想環境を構築しました。この紀記事はその設定の手順になります。

## バーチャルマシン（vagrant）
仮想環境を管理するために vagrant というツールを使ってるんですが、これは任意です。なお `Vagrantfile` は以下のようになります。
```
Vagrant.configure("2") do |config|
  config.vm.box = "generic/freebsd12"
  config.vm.synced_folder "proj/", "/home/vagrant/proj"
end
```
- `generic/freebsd12` というイメージを使用する
- ホスト上の `./proj/` というフォルダをVMの `/home/vagrant/proj` に同期する（`rsync`利用）

`vagrant up` というコマンドでVMを立ち上げることができます。初起動時、vagrant が `generic/freebsd12` のイメージをダウンロードして展開してくれます。私がやったとき、`rsync`も自動的にインストールしてくれました。最後に `vagrant ssh` でVMに接続することができます。

FreeBSDの世界へようこそ！

## rsync によるファイル同期の注意点２つ
- VMを起動しても、同期が自動的に開始されないため、`vagrant rsync-auto &`を自ら実行する必要があります。
- 同期はホストからVMに、一方通行となります。したがってVM側にファイルの変更があっても同期されず、注意が必要。

## パッケージミラーの設定
デフォルト・ミラーが米国に在するので、日本から使うと割と遅いです。そのため、国内のミラーの設定をおすすめします。

下記、公式ミラー「ftp4.jp.FreeBSD.org」を設定しますが、公式ミラー一覧は[こちら](https://www.freebsd.org/doc/handbook/mirrors-ftp.html#mirrors-jp-ftp)です。
```
FreeBSD: {
  url: "pkg+ftp://ftp4.jp.FreeBSD.org/${ABI}/quarterly", # <- ここ変えたよ
  mirror_type: "srv",
  signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg",
  enabled: yes
}
```
※設定ファイル名：`/etc/pkg/FreeBSD.conf`

設定の変更後に必ず `pkg update` を実行しましょう。

## カーネルのソースファイルを入手
カーネルのソースコードをGithubでの参照はいいですが、時にはローカル環境にコピーがあると便利です。

あらゆるFTPミラーから、[ソースコードがダウロード可能です](ftp://ftp4.jp.freebsd.org/pub/FreeBSD/releases/amd64/amd64/12.1-RELEASE/)。

```
ftp ftp://ftp4.jp.freebsd.org/pub/FreeBSD/releases/amd64/amd64/12.1-RELEASE/src.txz
```

※コツ！`tar Jtf src.txz` で、アーカイブを解凍せずに中身を確認することができます。

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
`/` フォルダから解凍コマンドを実行すると、ソースコードは `/usr/src` 以下に置いてくれます。

```
cd /
tar Jxvf /root/src.txz
```

## カーネルモジュールの例（Hello World）

> **注意：** <br>
> `proj/` 以下の開発・ファイル編集など、必ずホストにて行うように気をつけましょう。<br>
> コンパイル（`make`）はVM側で行います。<br>

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

ホスト側にソースが更新される際、rsyncで同期されます。結果としてVM側コンパイルアウトプットは消され、綺麗になります。
```
$ ==> default: Rsyncing folder: 省略/proj/ => /home/vagrant/proj
$ ls
Makefile    hello.c
$
```

## Hiding from cats

`/usr/bin/cat` is a tool which reads data from one locations and writes it to another; in most cases, it is used to read text from a file and write it to STDOUT. Cat also supports some control characters, such as line-feeds `\f`, carriage returns `\r`, and newlines `\n`.

Here's a fun little proof-of-concept of how `\r` could be used to hide shell-script commands from cat:
```py
cmd_h = "echo 'You forgot to check `cat -A`!' > oops" # hidden
cmd_v = "echo 'Hello world!'"                         # visible

with open("test.sh", "w") as f:
	output = "#!/bin/sh\n"
	output += cmd_h + ";" + cmd_v + " #\r" + cmd_v + " " * (len(cmd_h) + 3) + "\n"
	f.write(output)
```

This abuses cat's default behavior of rendering carriage return `\r` characters.
Essentially, a `\r` will move the cursor back to the beginning of the line, and characters printed thereafter will be written over (overwrite) anything that was printed previously. This is also why we append spaces at the end of the string.

Therefore, when we run `cat test.sh`:
```
$ cat test.sh
#!/bin/sh
echo 'Hello world!'
$
```

However, running the file will really execute:
```sh
echo 'You forgot to check `cat -A`!' > oops
echo 'Hello world!'
```
```
$ ls
test.sh
$ sh ./test.sh
Hello world!
$ ls
oops  test.sh
$ cat oops
You forgot to check `cat -A`!
$
```

Finally, there are three ways of catching this:
1. The filesize of `test.sh` does not match the contents as printed by cat.
2. Opening the file in an *editor*, such as `vi`, `vim`, or `nano`, or a *pager* like `less`.
3. If we use `cat -A ./test.sh` instead, rendering of control characters is disabled:

```
$ cat -A test.sh
#!/bin/sh$
echo 'You forgot to check `cat -A`!' > oops;echo 'Hello world!' #^Mecho 'Hello world!'                                              $
```

Unfortunately, when downloading a script from the Internet, most people do not meticulously check the scripts they are running. Of the small percentage of those who do, many rely on `/usr/bin/cat` to do so. This attack can be used to slip an attack past even those who bother to check the code with cat.

From now on, let's use something safer, such as `less`, when we review scripts.



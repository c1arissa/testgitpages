---
layout: post
title:  Wargame Write-up OverTheWire Leviathan
author: Clarissa Podell
date:   2018-08-31
description: Article on bypassing data execution prevention in Windows 10
excerpt: Article on bypassing data execution prevention in Windows 10
comments: false
mathjax: false
toc: true
last_modified_at: 2017-03-09T13:01:27-05:00
categories:
   - linux
   - wargame/ctf
tags:
   - linux
   - wargame/ctf
   - exploit
---

# Introduction to Leviathan

[Leviathan](http://overthewire.org/wargames/leviathan/) is the third wargame on OverTheWire.org (rescued from intruded.net).

The Leviathan homepage provides a general description of the game, but no additional information for each level (intentionally).

#### Summary:

> Difficulty:     1/10
> Levels:         8
> Platform:   Linux/x86

#### Description:

> This wargame doesn't require any knowledge about programming - just a bit of common sense and some knowledge about basic nix commands. We had no idea that it'd be this hard to make an interesting wargame that wouldn't require programming abilities from the players. Hopefully we made an interesting challenge for the new ones.

* USERNAMES are somegame0, somegame1, ...
* Most LEVELS are stored in /somegame/.
* PASSWORDS for each level are stored in /etc/somegame_pass/.


Leviathan's levels are called leviathan0, leviathan1, … etc. and can be accessed on leviathan.labs.overthewire.org through SSH on port 2223.

Data for the levels can be found in the home directories. You can look at /etc/leviathan_pass for the various level passwords.

Write-access to home directories is disabled. It is advised to create a working directory with a hard-to-guess name in /tmp/.  You can use the command "mktemp -d" in order to generate a random and hard to guess directory in /tmp/.  Read-access to both /tmp/ and /proc/ is disabled so that users can not snoop on eachother. Files and directories with easily guessable or short names will be periodically deleted!


SSH Information

```
Host: leviathan.labs.overthewire.org
Port: 2223
```

Here's the command to login to each level through SSH, where X is replaced by the number of each level.

{% highlight bash %}
$ ssh leviathanX@leviathan.labs.overthewire.org -p 2223
{% endhighlight %}

## Level 0

To login to the first level use leviathan0 (username) / leviathan0 (password).

In this level, `.backup` is a hidden directory.


{% highlight bash %}
leviathan0@leviathan:~$ ls -la
total 24
drwxr-xr-x  3 root       root       4096 May 10 18:27 .
drwxr-xr-x 10 root       root       4096 May 10 18:27 ..
drwxr-x---  2 leviathan1 leviathan0 4096 May 10 18:27 .backup
-rw-r--r--  1 root       root        220 May 15  2017 .bash_logout
-rw-r--r--  1 root       root       3526 May 15  2017 .bashrc
-rw-r--r--  1 root       root        675 May 15  2017 .profile
{% endhighlight %}

`bookmarks.html` is the only file with data.  This is a large file with html code.  To find the password, we can just grep the output with "password".  (This was just a lucky guess!)

```bash
leviathan0@leviathan:~$ cd .backup
leviathan0@leviathan:~/.backup$ ls -la
total 140
drwxr-x--- 2 leviathan1 leviathan0   4096 May 10 18:27 .
drwxr-xr-x 3 root       root         4096 May 10 18:27 ..
-rw-r----- 1 leviathan1 leviathan0 133259 May 10 18:27 bookmarks.html
leviathan0@leviathan:~/.backup$ cat bookmarks.html | grep "password"
<DT><A HREF="http://leviathan.labs.overthewire.org/passwordus.html | This will be fixed later, the password for leviathan1 is ********** rioGegei8m" ADD_DATE="1155384634" LAST_CHARSET="ISO-8859-1" ID="rdf:#$2wIU71">password to leviathan1</A>
```

## Level 1

Login to the next level using the password found in Level 0.

```bash
clarissa@ubuntu:~$ ssh leviathan1@leviathan.labs.overthewire.org -p 2223
```

Let's check the home directory:

```bash
leviathan1@leviathan:~$ ls
check
leviathan1@leviathan:~$ file check
check: setuid ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a59dfd0a32a6badc54a17cd8e04091fd6f9d049a, not stripped
```

The general steps I take for each level is to `ls` the directory then run `file` on the given executable.  Based on the output, we have a setuid ELF 32-bit executable.  Next, run the program without arguments to see how it works.

```bash
leviathan1@leviathan:~$ ./check
password: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Wrong password, Good Bye ...
```

This program accepts arbitrary string input from the user and does some sort of comparison before printing "Wrong password, Good Bye ...".  Since we are dealing with a vulnerable program in a wargame, it's a safe assumption/bet that we are dealing with a C string library function.  

Let's fire up `gdb` and check out the disassembly of the `main` function.  The very first thing I'll do is change the assembly syntax to Intel using `set disassembly-flavor intel`.  

```bash
leviathan1@leviathan:~$ gdb -q ./check
Reading symbols from ./check...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
```

About halfway through the output is a call to `strcmp@plt`.  This function takes two arguments.

At line +129 in the disassembly of main, there's a call to `strcmp@plt`.  This could be interesting, so let's set a breakpoint here.  This function takes two arguments.  Based on the disassembly output, one argument is at `ebp-0x20` and the other at `ebp-0x1c`

```nasm
(gdb) disass main
Dump of assembler code for function main:
...
0x56555712 <+82>:	call   0x565554d0 <printf@plt>
---Type <return> to continue, or q <return> to quit---
0x56555717 <+87>:	add    esp,0x10
0x5655571a <+90>:	call   0x565554e0 <getchar@plt>
0x5655571f <+95>:	mov    BYTE PTR [ebp-0x1c],al
0x56555722 <+98>:	call   0x565554e0 <getchar@plt>
0x56555727 <+103>:	mov    BYTE PTR [ebp-0x1b],al
0x5655572a <+106>:	call   0x565554e0 <getchar@plt>
0x5655572f <+111>:	mov    BYTE PTR [ebp-0x1a],al
0x56555732 <+114>:	mov    BYTE PTR [ebp-0x19],0x0
0x56555736 <+118>:	sub    esp,0x8
0x56555739 <+121>:	lea    eax,[ebp-0x20] ; ARG1: PASSWORD
0x5655573c <+124>:	push   eax
0x5655573d <+125>:	lea    eax,[ebp-0x1c] ; ARG2: user data
0x56555740 <+128>:	push   eax
0x56555741 <+129>:	call   0x565554c0 <strcmp@plt>  <= set breakpoint
0x56555746 <+134>:	add    esp,0x10
0x56555749 <+137>:	test   eax,eax
0x5655574b <+139>:	jne    0x5655577a <main+186>
....
```

Next, run the program in `gdb` and provide an arbitrary argument to the `password:` prompt.  When the breakpoint hits `strcmp`, we can examine the memory contents in each argument.  We know that one argument will contain our input string and the other will have the password.  The command `x/s` will print the memory as a string.

```nasm
(gdb) b *main+129
Breakpoint 1 at 0x56555741
(gdb) r
Starting program: /home/leviathan1/check
password: aaaa

Breakpoint 1, 0x56555741 in main ()
(gdb) x/s $ebp-0x1c
0xffffd64c:	"aaa"
(gdb) x/s $ebp-0x20
0xffffd648:	"sex"
(gdb)
```

Once we enter the correct password, we get an elevated prompt where we have access to the next level's password.

```
leviathan1@leviathan:~$ ./check
password: sex
$ whoami
leviathan2
$ cat /etc/leviathan_pass/leviathan2
ougahZi8Ta
$
```

## Level 2

This level contains the file `printfile`.  I'll use `file` to get more information.

```bash
leviathan2@leviathan:~$ ls -la
total 28
drwxr-xr-x  2 root       root       4096 May 10 18:27 .
drwxr-xr-x 10 root       root       4096 May 10 18:27 ..
-rw-r--r--  1 root       root        220 May 15  2017 .bash_logout
-rw-r--r--  1 root       root       3526 May 15  2017 .bashrc
-rw-r--r--  1 root       root        675 May 15  2017 .profile
-r-sr-x---  1 leviathan3 leviathan2 7640 May 10 18:27 printfile
leviathan2@leviathan:~$ file printfile
printfile: setuid ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=d1b5e5f479cfe2970294b7e8b7af05257c24777f, not stripped
```

When we run the executable with no arguments, it prints a usage message.

```bash
leviathan2@leviathan:~$ ./printfile
*** File Printer ***
Usage: ./printfile filename
```

Create a directory and a file with a space in the name all in one go

```bash
leviathan2@melinda:~$ mkdir /tmp/cp2 && touch /tmp/cp2/file\ tmp.txt
leviathan2@melinda:~$ cd /tmp/cp2
leviathan2@melinda:/tmp/cp2$ ls -la
total 7864
drwxrwxr-x 2 leviathan2 leviathan2    4096 Dec 29 21:14 .
drwxrwx-wt 1 root       root       8036352 Dec 29 21:14 ..
-rw-rw-r-- 1 leviathan2 leviathan2       0 Dec 29 21:14 file tmp.txt #file we created
```

```bash
leviathan2@leviathan:/tmp/cp2$ ltrace ~/printfile "file tmp.txt"
__libc_start_main(0x565556c0, 2, 0xffffd6f4, 0x565557b0 `<unfinished ...>`
access("file tmp.txt", 4)                                        = 0
snprintf("/bin/cat file tmp.txt", 511, "/bin/cat %s", "file tmp.txt") = 21
geteuid()                                                        = 12002
geteuid()                                                        = 12002
setreuid(12002, 12002)                                           = 0
system("/bin/cat file tmp.txt"/bin/cat: file: No such file or directory
/bin/cat: tmp.txt: No such file or directory
 `<no return ...>`
--- SIGCHLD (Child exited) ---
`<... system resumed>` )                                           = 256
+++ exited (status 0) +++
```

We can see that the function access() and /bin/cat are being called on the file. What access() does is check permissions based on the process’ real user ID rather than the effective user ID.
While access does use the full file path, the cat on the file is not using the full file path. We can see this near the end of the output where /bin/cat/ is being called to tmp.txt as if it were a separate file, it’s really the second half of our filename. This can be exploited if we create a symbolic link from the password file to the file we created in /tmp.

```bash
leviathan2@leviathan:/tmp/cp2$ ln -s /etc/leviathan_pass/leviathan3 /tmp/cp2/file
leviathan2@leviathan:/tmp/cp2$ ls -la
total 20
drwxr-xr-x   2 leviathan2 leviathan2  4096 Aug 31 11:37 .
drwxrwx-wt 168 root       root       16384 Aug 31 11:31 ..
lrwxrwxrwx   1 leviathan2 leviathan2    30 Aug 31 11:37 file -> /etc/leviathan_pass/leviathan3
-rw-r--r--   1 leviathan2 leviathan2     0 Aug 31 11:31 file tmp.txt
```

```bash
leviathan2@leviathan:/tmp/cp2$ ~/printfile "file"
You cant have that file...
leviathan2@leviathan:/tmp/cp2$ ~/printfile "file tmp.txt"
Ahdiemoo1j
/bin/cat: tmp.txt: No such file or directory
```

This all works because /printfile is owned by leviathan3. Access will call the symlink with that privilege. But we also needed to utilize a syntax hack to make it work, hence the filename with a space in it.

## Level 3

```bash
leviathan3@leviathan:~$ ls -la
total 32
drwxr-xr-x  2 root       root        4096 May 10 18:27 .
drwxr-xr-x 10 root       root        4096 May 10 18:27 ..
-rw-r--r--  1 root       root         220 May 15  2017 .bash_logout
-rw-r--r--  1 root       root        3526 May 15  2017 .bashrc
-rw-r--r--  1 root       root         675 May 15  2017 .profile
-r-sr-x---  1 leviathan4 leviathan3 10488 May 10 18:27 level3
leviathan3@leviathan:~$ file level3
level3: setuid ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=01dcd65bfc1afa58036f0100acbce686868f204f, not stripped
```

This is similar to level 1.

```bash
leviathan3@leviathan:~$ ./level3
Enter the password> aaaaaaaaaaaaaaaaaaaaa
bzzzzzzzzap. WRONG
```

leviathan3@leviathan:~$ ltrace ./level3
__libc_start_main(0x565557b4, 1, 0xffffd744, 0x56555870 <unfinished ...>
strcmp("h0no33", "kakaka")                                       = -1
printf("Enter the password> ")                                   = 20
fgets(Enter the password> aaaaaaaaaaaaaaaaaaaa
"aaaaaaaaaaaaaaaaaaaa\n", 256, 0xf7fc55a0)                 = 0xffffd550
strcmp("aaaaaaaaaaaaaaaaaaaa\n", "snlprintf\n")                  = -1
puts("bzzzzzzzzap. WRONG"bzzzzzzzzap. WRONG
)                                       = 19
+++ exited (status 0) +++


leviathan3@leviathan:~$ ./level3
Enter the password> snlprintf
[You've got shell]!
$ whoami
leviathan4
$ cat /etc/leviathan_pass/leviathan4
vuH0coox6m
$

## Level 4

leviathan4@leviathan:~$ ls -la
total 24
drwxr-xr-x  3 root root       4096 May 10 18:27 .
drwxr-xr-x 10 root root       4096 May 10 18:27 ..
-rw-r--r--  1 root root        220 May 15  2017 .bash_logout
-rw-r--r--  1 root root       3526 May 15  2017 .bashrc
-rw-r--r--  1 root root        675 May 15  2017 .profile
dr-xr-x---  2 root leviathan4 4096 May 10 18:27 .trash
leviathan4@leviathan:~$
leviathan4@leviathan:~$ cd .trash
leviathan4@leviathan:~/.trash$ ls -la
total 16
dr-xr-x--- 2 root       leviathan4 4096 May 10 18:27 .
drwxr-xr-x 3 root       root       4096 May 10 18:27 ..
-r-sr-x--- 1 leviathan5 leviathan4 7556 May 10 18:27 bin
leviathan4@leviathan:~/.trash$
leviathan4@leviathan:~/.trash$ file bin
bin: setuid ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=d3808cd51b87c957fdaa96b31a561c7aa414f952, not stripped
leviathan4@leviathan:~/.trash$
leviathan4@leviathan:~/.trash$ ./bin
01010100 01101001 01110100 01101000 00110100 01100011 01101111 01101011 01100101 01101001 00001010
leviathan4@leviathan:~/.trash$
leviathan4@leviathan:~/.trash$ ltrace ./bin
__libc_start_main(0x56555640, 1, 0xffffd724, 0x56555750 <unfinished ...>
fopen("/etc/leviathan_pass/leviathan5", "r")                     = 0
+++ exited (status 255) +++
leviathan4@leviathan:~/.trash$

leviathan4@leviathan:~/.trash$ echo 01010100 01101001 01110100 01101000 00110100 01100011 01101111 01101011 01100101 01101001 00001010 | perl -lape '$_=pack"(B8)*",@F'
Tith4cokei

leviathan4@leviathan:~/.trash$

>>> n = int('0b01010100', 2)
>>> binascii.unhexlify('%x' % n)
'T'
>>>


leviathan4@leviathan:~/.trash$ gdb -q ./bin
Reading symbols from ./bin...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) disass main
Dump of assembler code for function main:
   0x00000640 <+0>:	lea    ecx,[esp+0x4]
   0x00000644 <+4>:	and    esp,0xfffffff0
   0x00000647 <+7>:	push   DWORD PTR [ecx-0x4]
   0x0000064a <+10>:	push   ebp
   0x0000064b <+11>:	mov    ebp,esp
   0x0000064d <+13>:	push   ebx
   0x0000064e <+14>:	push   ecx
   0x0000064f <+15>:	sub    esp,0x10
   0x00000652 <+18>:	call   0x510 <__x86.get_pc_thunk.bx>
   0x00000657 <+23>:	add    ebx,0x19a9
   0x0000065d <+29>:	sub    esp,0x8
   0x00000660 <+32>:	lea    eax,[ebx-0x1830] ; MODE
   0x00000666 <+38>:	push   eax
   0x00000667 <+39>:	lea    eax,[ebx-0x182c] ; FILENAME
   0x0000066d <+45>:	push   eax
   0x0000066e <+46>:	call   0x4a0 <fopen@plt>
   0x00000673 <+51>:	add    esp,0x10
   0x00000676 <+54>:	mov    DWORD PTR [ebp-0x18],eax
   0x00000679 <+57>:	cmp    DWORD PTR [ebp-0x18],0x0
   0x0000067d <+61>:	jne    0x689 <main+73>
   0x0000067f <+63>:	mov    eax,0xffffffff
   0x00000684 <+68>:	jmp    0x739 <main+249>
...
End of assembler dump.
(gdb) b *main+46
Breakpoint 1 at 0x66e
(gdb) r
Starting program: /home/leviathan4/.trash/bin

Breakpoint 1, 0x5655566e in main ()
(gdb) x/s $eax
0x565557d4:	"/etc/leviathan_pass/leviathan5"
(gdb) x/s $ebx-0x1830
0x565557d0:	"r"
(gdb) x/s $ebx-0x182c
0x565557d4:	"/etc/leviathan_pass/leviathan5"

I'll create a working directory and a file to save the output from `./bin`:

```bash
leviathan4@leviathan:~/.trash$ mkdir /tmp/lvl4 && touch /tmp/lvl4/password.bin
leviathan4@leviathan:~/.trash$ ./bin > /tmp/lvl4/password.bin
```

I'll use the output file as input to a python script that converts each binary string into a letter.

binary to hex:
>>> hex(int('01010100', 2))
u'0x54'
# .decode('hex') uses binascii.unhexlify() on Python 2.
>>> n[2:].decode('hex')
'T'
>>> import codecs
>>> codecs.decode("7061756c", "hex")
'paul'
>>> bytearray.fromhex("7061756c").decode()
u'paul'
>>> bytearray.fromhex(n[2:]).decode()
u'T'

```python
#!/usr/bin/env python

import binascii

# Read binary encoded password from ./bin output
with open("/tmp/lvl4/password.bin", "rb") as f:
    data = f.read()

print "[*] Input:\n%s" % data

# Create list of binary strings by splitting input on each space
bin_list = data.rstrip().split(' ')

print "[*] Converting Binary to ASCII:"

password = ""

# Iterate through each binary string in list EXCEPT for the
# last list item since 00001010=0x0A='\n' (new line)
for b in bin_list[:-1]:

    password += binascii.unhexlify('%x' % int(b, 2))
    print "%s => %s" % (b, password[-1])

print "\n[*] PASSWORD:\n%s" % password
```

```bash
leviathan4@leviathan:/tmp/lvl4$ vim leviathan4.py
leviathan4@leviathan:/tmp/lvl4$ python leviathan4.py
[*] Input:
01010100 01101001 01110100 01101000 00110100 01100011 01101111 01101011 01100101 01101001 00001010

[*] Converting Binary to ASCII:
01010100 => T
01101001 => i
01110100 => t
01101000 => h
00110100 => 4
01100011 => c
01101111 => o
01101011 => k
01100101 => e
01101001 => i

[*] PASSWORD:
Tith4cokei
```

## Level 5

SYMLINKS

```bash
leviathan5@leviathan:~$ ls -la leviathan5
-r-sr-x--- 1 leviathan6 leviathan5 7764 May 10 18:27 leviathan5
leviathan5@leviathan:~$ ./leviathan5
Cannot find /tmp/file.log
```

When we run the binary in Leviathan5’s home directory, it appears to be attempting to read from a file in /tmp. The binary is owned by Leviathan6 but belongs to the Leviathan5‘s group. Therefore, it can pull Leviathan6’s password.

Since we need Leviathan 6's pass, symlink that to the log we create within the same command:

```bash
leviathan5@leviathan:~$ ln -s /etc/leviathan_pass/leviathan6 /tmp/file.log
leviathan5@leviathan:~$ ls -la /tmp/file.log
lrwxrwxrwx 1 leviathan5 leviathan5 30 Aug 31 23:31 /tmp/file.log -> /etc/leviathan_pass/leviathan6
```

Now run the binary, which apparently reads whatever is in /tmp/file.log

```bash
leviathan5@leviathan:~$ ./leviathan5
UgaoFee4li
```

The following command creates a symbolic link at the command-line interface (shell):

 ln -s target_path link_path

target_path is the relative or absolute path to which the symbolic link should point. Usually the target will exist, although symbolic links may be created to non-existent targets. link_path is the path of the symbolic link.

After creating the symbolic link, it may generally be treated as an alias for the target. Any file system management commands (e.g., cp, rm) may be used on the symbolic link. Commands which read or write file contents will access the contents of the target file.

## Level 6

```bash
leviathan6@leviathan:~$ ./leviathan6
usage: ./leviathan6 <4 digit code>
leviathan6@leviathan:~$ ./leviathan6 1234
Wrong
```

This binary is straight forward.  I could have wrote a script to brute-force all combinations between 0000-9999, but instead I used the debugger.

leviathan6@leviathan:~$ gdb -q ./leviathan6
Reading symbols from ./leviathan6...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) disass main
Dump of assembler code for function main:
   0x000006c0 <+0>:	lea    ecx,[esp+0x4]
   0x000006c4 <+4>:	and    esp,0xfffffff0
   0x000006c7 <+7>:	push   DWORD PTR [ecx-0x4]
   0x000006ca <+10>:	push   ebp
   0x000006cb <+11>:	mov    ebp,esp
   0x000006cd <+13>:	push   esi
   0x000006ce <+14>:	push   ebx
   0x000006cf <+15>:	push   ecx
   0x000006d0 <+16>:	sub    esp,0x1c
   0x000006d3 <+19>:	call   0x590 <__x86.get_pc_thunk.bx>
   0x000006d8 <+24>:	add    ebx,0x1928
   0x000006de <+30>:	mov    eax,ecx
   0x000006e0 <+32>:	mov    DWORD PTR [ebp-0x1c],0x1bd3  ; PASSWORD STORED ON STACK
   0x000006e7 <+39>:	cmp    DWORD PTR [eax],0x2  ; argc = 2
   0x000006ea <+42>:	je     0x70e <main+78>
   0x000006ec <+44>:	mov    eax,DWORD PTR [eax+0x4]
   0x000006ef <+47>:	mov    eax,DWORD PTR [eax]
   0x000006f1 <+49>:	sub    esp,0x8
   0x000006f4 <+52>:	push   eax
   0x000006f5 <+53>:	lea    eax,[ebx-0x1800]
   0x000006fb <+59>:	push   eax
   0x000006fc <+60>:	call   0x4c0 <printf@plt>
---Type <return> to continue, or q <return> to quit---
   0x00000701 <+65>:	add    esp,0x10
   0x00000704 <+68>:	sub    esp,0xc
   0x00000707 <+71>:	push   0xffffffff
   0x00000709 <+73>:	call   0x500 <exit@plt>
   0x0000070e <+78>:	mov    eax,DWORD PTR [eax+0x4]
   0x00000711 <+81>:	add    eax,0x4
   0x00000714 <+84>:	mov    eax,DWORD PTR [eax]
   0x00000716 <+86>:	sub    esp,0xc
   0x00000719 <+89>:	push   eax
   0x0000071a <+90>:	call   0x530 <atoi@plt> ; convert ASCII arg to integer
   0x0000071f <+95>:	add    esp,0x10
   0x00000722 <+98>:	cmp    eax,DWORD PTR [ebp-0x1c] ; PASSWORD (COMPARE INPUT WITH CORRECT NUMBER)
   0x00000725 <+101>:	jne    0x754 <main+148>         ; jumps past system()
   0x00000727 <+103>:	call   0x4d0 <geteuid@plt>
   0x0000072c <+108>:	mov    esi,eax
   0x0000072e <+110>:	call   0x4d0 <geteuid@plt>
   0x00000733 <+115>:	sub    esp,0x8
   0x00000736 <+118>:	push   esi
   0x00000737 <+119>:	push   eax
   0x00000738 <+120>:	call   0x510 <setreuid@plt>
   0x0000073d <+125>:	add    esp,0x10
   0x00000740 <+128>:	sub    esp,0xc
   0x00000743 <+131>:	lea    eax,[ebx-0x17e6]
---Type <return> to continue, or q <return> to quit---
   0x00000749 <+137>:	push   eax
   0x0000074a <+138>:	call   0x4f0 <system@plt>
   0x0000074f <+143>:	add    esp,0x10
   0x00000752 <+146>:	jmp    0x766 <main+166>
   0x00000754 <+148>:	sub    esp,0xc
   0x00000757 <+151>:	lea    eax,[ebx-0x17de]
   0x0000075d <+157>:	push   eax
   0x0000075e <+158>:	call   0x4e0 <puts@plt>
   0x00000763 <+163>:	add    esp,0x10
   0x00000766 <+166>:	mov    eax,0x0
   0x0000076b <+171>:	lea    esp,[ebp-0xc]
   0x0000076e <+174>:	pop    ecx
   0x0000076f <+175>:	pop    ebx
   0x00000770 <+176>:	pop    esi
   0x00000771 <+177>:	pop    ebp
   0x00000772 <+178>:	lea    esp,[ecx-0x4]
   0x00000775 <+181>:	ret    
End of assembler dump.
(gdb)

```bash
(gdb) b *main+98
Breakpoint 1 at 0x722
(gdb) r 1234
Starting program: /home/leviathan6/leviathan6 1234

Breakpoint 1, 0x56555722 in main ()
(gdb) x/d $ebp-0x1c
0xffffd63c:	7123
(gdb) i r eax
eax            0x4d2	1234
```

Looking at the disassembly output (without knowing much about how the program works), my goal is to choose a control-flow path that executes the call to `system` (line +138).  This gives our elevated /bin/sh shell.

It looks like the line that determines the path is the line at 93 compare instruction.  If the comparison fails, execution jumps past the system call.  Otherwise, execution leads into system.

```bash
leviathan6@leviathan:~$ ./leviathan6 7123
$ whoami
leviathan7
$ cat /etc/leviathan_pass/leviathan7
ahy7MaeBo9
$
```

## Level 7

```bash
leviathan7@leviathan:~$ ls -la
total 24
drwxr-xr-x  2 root       root       4096 May 10 18:27 .
drwxr-xr-x 10 root       root       4096 May 10 18:27 ..
-rw-r--r--  1 root       root        220 May 15  2017 .bash_logout
-rw-r--r--  1 root       root       3526 May 15  2017 .bashrc
-rw-r--r--  1 root       root        675 May 15  2017 .profile
-r--r-----  1 leviathan7 leviathan7  178 May 10 18:27 CONGRATULATIONS
leviathan7@leviathan:~$ ls
CONGRATULATIONS
leviathan7@leviathan:~$ cat CONGRATULATIONS
Well Done, you seem to have used a *nix system before, now try something more serious.
(Please don't post writeups, solutions or spoilers about the games on the web. Thank you!)
```

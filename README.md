# qemu-vm-escape

This is an exploit for [CVE-2019-6778](https://bugzilla.redhat.com/show_bug.cgi?id=1664205), a heap buffer overflow in slirp:tcp_emu(). For
more information, see the [writeup](writeup_zh.md) (Sorry, only Chinese version available now) and the [slides](Tensec2019-Vulnerability Discovery and Exploitation of Virtualization Solutions for Cloud Computing and Desktops.pdf) for the talk in Tensec 2019 by [Marco](https://twitter.com/marcograss) and [me](https://twitter.com/KiraCxy).

## Environment

```shell
$ ./qemu-system-x86_64 --version
QEMU emulator version 3.1.50 (v3.1.0-456-g9b2e891ec5-dirty)
Copyright (c) 2003-2018 Fabrice Bellard and the QEMU Project developers
```

Command used to start QEMU

```shell
./qemu-system-x86_64_exp -drive file=ubuntu-18.04-desktop-amd64.snapshot.qcow2,format=qcow2 -enable-kvm -m 2G -L ./pc-bios -smp 1 -device VGA -net user,hostfwd=tcp::2222-:22 -net nic
```

## Run

To simply verify the QEMU is vulnerable, run `sudo nc -lvv 113` on the host. Then compile and run the [crash poc](crash_poc.c) in the guest.

For the exploit:

Compile

```shell
gcc -o exp exp.c
```

Set MTU for the network card before running the exploit

```shell
ifconfig ens2 mtu 9000 up
```

Then

```shell
./exp
```


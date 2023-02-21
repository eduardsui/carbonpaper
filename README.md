# carbonpaper
lightweight realtime, zero-knowledge directory sync over network

What it is?
-----------
carbonpaper is a lightweight simple yet efficient real-time file syncronizer across multiple servers. It uses a simple network protocol, an asynchronous socket, Ed25519 signature/verify, x25519 key exchange and chacha20 for network traffic encryption.

Main features:
- fast
- bidirectional
- moderately secured
- [zero-knowledge proof](https://en.wikipedia.org/wiki/Zero-knowledge_proof)
- both off-line and real-time sync supported
- low network overheaded
- all file synchronization is based on mtime (newer file always wins)

Disadvantages:
- atomic write/reads (entire file is synchronized at once - no partial updates)
- default file size limit is 1.2Gb (files larger than 1.2Gb will not be synchronized)


Compiling
-----------

To compile, simply run:

``gcc -O2 carbonpaper.c -o carbonpaper``

or

``clang -fblocks carbonpaper.c -lBlocksRuntime -o carbonpaper``

Note that it uses [doops](https://github.com/eduardsui/doops) event scheduler. It can be compiled with both gcc and clang.
It currently works on linux (heavily depends on [inotify](https://man7.org/linux/man-pages/man7/inotify.7.html)) and has basic support on Windows. On systems without inotify(FreeBSD, macOS) you may still be able to compile it, but the sync will be unidirectional.

Usage
-----------

First you need to create a key:

`$ carbonpaper --genkey .`

The resulting `.carbonpaper.key` must pe copied on all the servers.

Then, on each machine:

`$ carbonpaper --host ip1 --host ip2 ~/dir/to/sync/`

Note: file delete sync is disabled by default. You can enable it by running with `--enable-delete`

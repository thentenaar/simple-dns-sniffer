Simple DNS Sniffer
==================

Background
----------

I was tasked with implementing this as a follow-up to a job interview
some time ago, and since I found it interesting, I figured I would
finally get around to publishing it. It can be useful for people wanting
to learn how to sniff traffic with libpcap from a simple example of a
real-world use case.

This "project" went from inception to completion in the span of two
evenings, so the code is far from perfect. But, it does exactly what
it was specified to do.

This README was also part of the documentation which I delivered upon
completion. As for their reaction, they were quite pleased with the
documentation, the functionality, and the code itself.

For the curious: I declined the offer, but it was an enjoyable exercise.

Synopsis
--------

```
# make clean all
# ./sniffer -h
./sniffer [-i interface] [-s snaplen] [-t timeout] [-p]

        -i interface: Interface to capture on
        -s snaplen:   Snapshot length / packet buffer size
        -t timeout:   Maximum read timeout (in milliseconds)
        -p:           Enable promiscuous mode

         Defaults: -i any -s 2048 -t 1000
```

Assuming that libpcap is able to capture, the sniffer will run
until the process receives a termination signal, or a fatal
error within libpcap occurs. Corrupted/incomplete packets are
silently dropped, save for cases that might arise due to
memory corruption or a flaw in libpcap.

Sniffing DNS over TCP as well as UDP is supported.

Assumptions
-----------

* This program is a demonstrative example of a prototype application
  using libpcap to sniff DNS traffic.

* "DNS" refers to the Domain Name System protocol specified in
   RFC 1035.

    Not all Resource Record (RR) types are handled, as some are
    obsolete, and I was unable to quickly test the others.

* This program must be run as root, or as a user with sufficient
  capabilities (e.g. ``CAP_NET_ADMIN``).

* Output is based on DNS responses only

    Only the responses are needed to generate the output
    as specified. As an optimization, the code uses a filter
    specifically designed to select only DNS responses by
    checking that the QR bit in the DNS header is set.

* The code is not thread-safe, as thread-safety wasn't a requirement.

DNS RRs Supported
------------------

* RFC 1035:
    A, NS, CNAME, NULL, PTR, MX, TXT

* RFC 1886:
    AAAA

NOTE: For NULL, the application prints the RR type, but
none of the data, as it can be anything, as long as it's
size is less than 65536 bytes. (RFC 1035 Sec. 3.3.10)

Output
------

Each output line is:
```
Timestamp Question_Type Question_Label Response_Data
```

This is obtained by correlating the question type with the
response RR's type; and using the first reponse that matches
the RR type that was asked for.

Capturing on 'any':
```
# ./sniffer
1426464428 AAAA  google.ru                      2a00:1450:4013:c00::5e
1426464456 TXT   hentenaar.com                  google-site-verification=UVHRy4rkGATkxae7aLkjN8YW7H1Xv1X20oospOZ_Uy8
1426464463 MX    google.com                     10 aspmx.l.google.com
1426464474 PTR   146.198.21.8.in-addr.arpa      alb56.clearspring.com
1426464484 A     hentenaar.com                  54.243.160.109
1426464490 CNAME www.hentenaar.com              hentenaar.com
1426464493 A     talkgadget.google.com          173.194.65.113
```

Capturing on 'wlan0':
```
# ./sniffer -i wlan0
1426464653 A     www.hentenaar.com              54.243.160.109
1426464656 CNAME www.hentenaar.com              hentenaar.com
1426464664 TXT   hentenaar.com                  google-site-verification=UVHRy4rkGATkxae7aLkjN8YW7H1Xv1X20oospOZ_Uy8
1426464712 A     i.ytimg.com                    173.194.65.100
1426464717 A     r6---sn-5hn7snl6.googlevideo.com 173.194.50.203
1426464717 A     googleads.g.doubleclick.net    173.194.65.157
```

Features Unimplemented
----------------------

* Lookup of the pid / process name

    For traffic originating from the local machine, this can be done by
	peeking at the relevant files in ``/proc/net`` to locate the inode
	of the destination port for the response packet, and then correlating
	that with the target of the links in ``/proc/pid/fds``.  However this
	approach will not work for this use case, as there's a race condition
	between the application receiving the response, and closing the socket;
	and  the sniffer handling the packet. This method is used by tools
    such as lsof and netstat, and is better suited for tracking
    processes with bound / longer-lived sockets.

    One alternative would be to do the lookup when the question
    is sent out, but that would be equally racy, and this feature
    being a "nice to have" was only an afterthought.

    In order to do this properly, I'd have to look at whether or not
    the kernel instrumentation interface (a la Systemtap) or the
    auditing system might be of more help, at least in eliminating
    the race condition with /proc probing. The caveat with this
    approach, is that then I'd be making assumptions about the
    configuration of the kernel on the machine upon which the code
    would be running.

    For demonstrative purposes, I've provided code in the
    ``extra`` directory that attempts this via ``/proc`` probing.
	It's still a bit rough but is merely intended to demonstrate
	the technique.

Memory Usage
------------

The VmSize stays steady, as expected. In order to save
on stack space, larger buffers are allocated in the
.bss section.
```
$ cat /proc/.../status
VmPeak:    13152 kB
VmSize:    13152 kB
VmHWM:      1012 kB
VmRSS:      1012 kB
VmData:      228 kB
VmStk:       136 kB
VmExe:        12 kB
```

Code Size
---------

With ``-O2``:
```
$ size sniffer
   text    data     bss     dec     hex filename
   8390    1000   16704   26094    65ee sniffer
```

With ``-Os``:
```
$ size sniffer
   text    data     bss     dec     hex filename
   7743     992   16672   25407    633f sniffer
```

These measurements were taken on a system with PIE and SSP enabled.
Not bad for 432 lines of code according to David A. Wheeler's
'SLOCCount'.

With these measurements keep in mind that they may vary from one system
to another, depending on your architecture, kernel version and
configuration, the C library being linked against, etc.

Ideas for Future Development
----------------------------

* Implement the unhandled RFC 1035 types.
* Implement further DNS extensions.
* Research integration with the kernel's auditing / instrumentation
  framework  for better tracking of requests.
* Test on libc implementations other than glibc (i.e. uclibc.)
* Further optimize the code.


EAI Support for Qmail
===============

Here you'll find SMTPUTF8 support for qmail, sponsored by
[CNNIC](http://cnnic.com.cn/index.htm). SMTPUTF8 allows using unicode in
email addresses,
आर्न्ट@यूनिवर्सल.भारत is a valid email address and it's
[very simple to implement](http://rant.gulbrandsen.priv.no/eai/one-minute-guide).

The branch [original](https://github.com/arnt/qmail-smtputf8/tree/original) contains
netqmail 1.06.

The branch [smtputf8-cleartext](https://github.com/arnt/qmail-smtputf8/tree/smtputf8-cleartext)
contains a patch for (EHLO and) SMTPUTF8 on top of original.

The branch
[smtputf8-tls](https://github.com/arnt/qmail-smtputf8/tree/smtputf8-tls)
contains a TLS patch and a patch for SMTPUTF8 on top of original. Each
patch is a single commit.

The TLS patch is old; it's the one from Gentoo linux and probably not
something you want to use on other platforms. My patch should apply easily
on top of any of the many TLS patches I've seen for Qmail.

My blog contains
[a posting about postfix, sendmail and this code](http://rant.gulbrandsen.priv.no/programming/three-programs-one-feature)
and [a few other relevant postings](http://rant.gulbrandsen.priv.no/eai).
The [eai-test-messages](https://github.com/arnt/eai-test-messages) repository
contains some test messages.

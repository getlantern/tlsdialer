package tlsdialer contains a customized version of crypto/tls.Dial that allows
control over whether or not to send the ServerName extension in the client
handshake.

v1 is the current version.  Import and doc information on
[gopkg.in](http://gopkg.in/getlantern/tlsdialer.v1).
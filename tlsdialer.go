// package tlsdialer contains a customized version of crypto/tls.Dial that
// allows control over whether or not to send the ServerName extension in the
// client handshake.
package tlsdialer

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"time"

	"github.com/getlantern/golog"
)

var (
	log = golog.LoggerFor("tlsdialer")
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "tls: DialWithDialer timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// A tls.Conn along with timings for key steps in establishing that Conn
type ConnWithTimings struct {
	// Conn: the conn resulting from dialing
	Conn *tls.Conn
	// ResolutionTime: the amount of time it took to resolve the address
	ResolutionTime time.Duration
	// ConnectTime: the amount of time that it took to connect the socket
	ConnectTime time.Duration
	// HandshakeTime: the amount of time that it took to complete the TLS
	// handshake
	HandshakeTime time.Duration
}

// Like crypto/tls.Dial, but with the ability to control whether or not to
// send the ServerName extension in client handshakes through the sendServerName
// flag.
//
// Note - if sendServerName is false, the VerifiedChains field on the
// connection's ConnectionState will never get populated.
func Dial(network, addr string, sendServerName bool, config *tls.Config) (*tls.Conn, error) {
	return DialWithDialer(new(net.Dialer), network, addr, sendServerName, config)
}

// Like crypto/tls.DialWithDialer, but with the ability to control whether or
// not to send the ServerName extension in client handshakes through the
// sendServerName flag.
//
// Note - if sendServerName is false, the VerifiedChains field on the
// connection's ConnectionState will never get populated.
func DialWithDialer(dialer *net.Dialer, network, addr string, sendServerName bool, config *tls.Config) (*tls.Conn, error) {
	result, err := DialForTimings(dialer, network, addr, sendServerName, config)
	return result.Conn, err
}

// Like DialWithDialer but returns a data structure including timings.
func DialForTimings(dialer *net.Dialer, network, addr string, sendServerName bool, config *tls.Config) (*ConnWithTimings, error) {
	result := &ConnWithTimings{}

	// We want the Timeout and Deadline values from dialer to cover the
	// whole process: TCP connection and TLS handshake. This means that we
	// also need to start our own timers now.
	timeout := dialer.Timeout

	if !dialer.Deadline.IsZero() {
		deadlineTimeout := dialer.Deadline.Sub(time.Now())
		if timeout == 0 || deadlineTimeout < timeout {
			timeout = deadlineTimeout
		}
	}

	var errChannel chan error

	if timeout != 0 {
		errChannel = make(chan error, 2)
		time.AfterFunc(timeout, func() {
			errChannel <- timeoutError{}
		})
	}

	log.Tracef("Resolving addr: %s", addr)
	start := time.Now()
	// TODO: make this subject to the timeout too
	resolved, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return result, err
	}
	result.ResolutionTime = time.Now().Sub(start)
	log.Tracef("Resolved addr %s to %s in %s", addr, resolved, result.ResolutionTime)

	log.Tracef("Dialing %s %s (%s)", network, addr, resolved)
	start = time.Now()
	rawConn, err := dialer.Dial(network, resolved.String())
	if err != nil {
		return result, err
	}
	result.ConnectTime = time.Now().Sub(start)
	log.Tracef("Dialed in %s", result.ConnectTime)

	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}
	hostname := addr[:colonPos]

	if config == nil {
		config = &tls.Config{}
	}

	serverName := config.ServerName

	if serverName == "" {
		log.Trace("No ServerName set, inferring from the hostname to which we're connecting")
		serverName = hostname
	}
	log.Tracef("ServerName is: %s", serverName)

	log.Trace("Copying config so that we can tweak it")
	configCopy := new(tls.Config)
	*configCopy = *config

	if sendServerName {
		log.Tracef("Setting ServerName to %s and relying on the usual logic in tls.Conn.Handshake() to do verification", serverName)
		configCopy.ServerName = serverName
	} else {
		log.Trace("Clearing ServerName and disabling verification in tls.Conn.Handshake(). We'll verify manually after handshaking.")
		configCopy.ServerName = ""
		configCopy.InsecureSkipVerify = true
	}

	conn := tls.Client(rawConn, configCopy)

	start = time.Now()
	if timeout == 0 {
		log.Trace("Handshaking immediately")
		err = conn.Handshake()
	} else {
		log.Trace("Handshaking on goroutine")
		go func() {
			errChannel <- conn.Handshake()
		}()
		err = <-errChannel
	}
	if err == nil {
		result.HandshakeTime = time.Now().Sub(start)
	}
	log.Tracef("Finished handshaking in: %s", result.HandshakeTime)

	if !sendServerName && err == nil && !config.InsecureSkipVerify {
		log.Trace("Manually verifying certificates")
		err = verifyServerCerts(conn, serverName, config)
	}
	if err != nil {
		log.Trace("Handshake or verification error, closing underlying connection")
		rawConn.Close()
		return result, err
	}

	result.Conn = conn
	return result, nil
}

func verifyServerCerts(conn *tls.Conn, serverName string, config *tls.Config) error {
	certs := conn.ConnectionState().PeerCertificates

	opts := x509.VerifyOptions{
		Roots:         config.RootCAs,
		CurrentTime:   time.Now(),
		DNSName:       serverName,
		Intermediates: x509.NewCertPool(),
	}

	for i, cert := range certs {
		if i == 0 {
			continue
		}
		opts.Intermediates.AddCert(cert)
	}
	_, err := certs[0].Verify(opts)
	return err
}

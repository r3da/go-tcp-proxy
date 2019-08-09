package proxy

import (
	"bytes"
	"crypto/tls"
	"github.com/eclipse/paho.mqtt.golang/packets"
	"io"
	"net"
)

const (
	TCP_PROXY  = "tcp"
	MQTT_PROXY = "mqtt"
)

// Proxy - Manages a Proxy connection, piping data between local and remote.
type Proxy struct {
	sentBytes     uint64
	receivedBytes uint64
	laddr, raddr  *net.TCPAddr
	lconn, rconn  io.ReadWriteCloser
	erred         bool
	errsig        chan bool
	tlsUnwrapp    bool
	tlsAddress    string
	tlsCfg        *tls.Config

	Matcher  func([]byte)
	Replacer func([]byte) []byte

	// Settings
	Log       Logger
	OutputHex bool
	ProxyType string
}

// New - Create a new Proxy instance. Takes over local connection passed in,
// and closes it when finished.
func New(lconn io.ReadWriteCloser, laddr, raddr *net.TCPAddr) *Proxy {
	return &Proxy{
		lconn:  lconn,
		laddr:  laddr,
		raddr:  raddr,
		erred:  false,
		errsig: make(chan bool),
		Log:    NullLogger{},
	}
}

// NewTLSUnwrapped - Create a new Proxy instance with a remote TLS server for
// which we want to unwrap the TLS to be able to connect without encryption
// locally
func NewTLSUnwrapped(lconn io.ReadWriteCloser, laddr, raddr *net.TCPAddr, addr string, tlsCfg *tls.Config) *Proxy {
	p := New(lconn, laddr, raddr)
	p.tlsUnwrapp = true
	p.tlsAddress = addr
	p.tlsCfg = tlsCfg
	return p
}

type setNoDelayer interface {
	SetNoDelay(bool) error
}

// Start - open connection to remote and start proxying data.
func (p *Proxy) Start() {
	defer p.lconn.Close()

	var err error
	//connect to remote
	if p.tlsUnwrapp {
		p.rconn, err = tls.Dial("tcp", p.tlsAddress, p.tlsCfg)
	} else {
		p.rconn, err = net.DialTCP("tcp", nil, p.raddr)
	}
	if err != nil {
		p.Log.Warn("Remote connection failed: %s", err)
		return
	}
	defer p.rconn.Close()

	//display both ends
	p.Log.Info("Opened %s >>> %s", p.laddr.String(), p.raddr.String())

	//bidirectional copy
	go p.pipe(p.lconn, p.rconn)
	go p.pipe(p.rconn, p.lconn)

	//wait for close...
	<-p.errsig
	p.Log.Info("Closed (%d bytes sent, %d bytes received)", p.sentBytes, p.receivedBytes)
}

func (p *Proxy) err(s string, err error) {
	if p.erred {
		return
	}
	//if err != io.EOF {
	p.Log.Warn(s, err)
	//}
	p.errsig <- true
	p.erred = true
}

func (p *Proxy) pipe(src, dst io.ReadWriter) {
	islocal := src == p.lconn

	var dataDirection string
	var directionPrefix string
	if islocal {
		directionPrefix = ">>> "
		dataDirection = "%d bytes sent%s"
	} else {
		directionPrefix = "<<< "
		dataDirection = "%d bytes received%s"
	}

	dataDirection = directionPrefix + dataDirection
	var byteFormat string
	if p.OutputHex {
		byteFormat = directionPrefix + "%x"
	} else {
		byteFormat = directionPrefix + "%s"
	}

	//directional copy (64k buffer)
	buff := make([]byte, 0xffff)
	for {
		n, err := src.Read(buff)
		if n == 0 && err != nil {
			p.err(directionPrefix + "Read failed '%s'\n", err)
			return
		}
		b := buff[:n]

		//execute match
		if p.Matcher != nil {
			p.Matcher(b)
		}

		//execute replace
		if p.Replacer != nil {
			b = p.Replacer(b)
		}

		//show output
		p.Log.Debug(dataDirection, n, "")
		p.Log.Trace(byteFormat, b)
		switch p.ProxyType {
		case MQTT_PROXY:
			pkt, _ := packets.ReadPacket(bytes.NewReader(b))
			if err == nil {
				p.Log.Trace(directionPrefix + "%s", pkt)
			} else {
				p.Log.Trace(directionPrefix + "%s", b)
			}
		case TCP_PROXY:
			p.Log.Trace(directionPrefix + "%s", b)
		}

		//write out result
		n, err = dst.Write(b)
		if err != nil {
			p.err(directionPrefix + "Write failed '%s'\n", err)
			return
		}
		if islocal {
			p.sentBytes += uint64(n)
		} else {
			p.receivedBytes += uint64(n)
		}
	}
}

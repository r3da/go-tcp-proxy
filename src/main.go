package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"strings"

	"proxy"
)

var (
	matchid = uint64(0)
	connid  = uint64(0)
	logger  proxy.ColorLogger

	localAddr     = flag.String("l", ":9999", "local address")
	localCertPath = flag.String("lcp", "", "local certificate path")
	localKeyPath  = flag.String("lkp", "", "local key path")

	remoteAddr     = flag.String("r", "localhost:80", "remote address")
	remoteCertPath = flag.String("rcp", "", "remote certificate path")
	remoteKeyPath  = flag.String("rkp", "", "remote key path")
	remoteCAPath   = flag.String("rcap", "", "remote certificate ca path. Will skip verifying remote cert if this is omitted")

	verbose     = flag.Bool("v", false, "display server actions")
	veryverbose = flag.Bool("vv", false, "display server actions and all tcp data")
	hex         = flag.Bool("h", false, "output hex")
	colors      = flag.Bool("c", false, "output ansi colors")
	proxyType   = flag.String("pt", "tcp", "Proxy type: tcp/mqtt")
	unwrapTLS   = flag.Bool("unwrap-tls", false, "remote connection with TLS exposed unencrypted locally")
	match       = flag.String("match", "", "match regex (in the form 'regex')")
	replace     = flag.String("replace", "", "replace regex (in the form 'regex~replacer')")
)

func main() {
	flag.Parse()

	logger := proxy.ColorLogger{
		Verbose: *verbose,
		Color:   *colors,
	}

	logger.Info("Proxying from %v to %v", *localAddr, *remoteAddr)

	laddr, err := net.ResolveTCPAddr("tcp", *localAddr)
	if err != nil {
		logger.Warn("Failed to resolve local address: %s", err)
		os.Exit(1)
	}
	raddr, err := net.ResolveTCPAddr("tcp", *remoteAddr)
	if err != nil {
		logger.Warn("Failed to resolve remote address: %s", err)
		os.Exit(1)
	}

	var listener net.Listener
	listener, err = net.ListenTCP("tcp", laddr)

	if *localKeyPath != "" && *localCertPath != "" {
		cert, err := tls.LoadX509KeyPair(*localCertPath, *localKeyPath)
		if err != nil {
			logger.Warn("Failed to load server certificate: %s", err.Error())
			os.Exit(1)
		}
		certificates := []tls.Certificate{cert}
		cacertpool := x509.NewCertPool()
		ca, err := ioutil.ReadFile(*localCertPath)
		if err != nil {
			log.Fatalf("Failed to append %s to RootCAs: %v", *localCertPath, err)
		}
		cacertpool.AppendCertsFromPEM(ca)

		localTLSConfig := &tls.Config{
			ClientAuth: tls.RequireAnyClientCert,
			Certificates: certificates,
		}
		listener = tls.NewListener(listener, localTLSConfig)
	}

	var remoteTlsConfig *tls.Config
	if *remoteCertPath != "" && *remoteKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(*remoteCertPath, *remoteKeyPath)
		if err != nil {
			logger.Warn("Failed to load server certificate: %s", err.Error())
			os.Exit(1)
		}
		certificates := []tls.Certificate{cert}

		remoteTlsConfig = &tls.Config{
			Certificates: certificates,
		}
		if *remoteCAPath != "" {
			cacertpool := x509.NewCertPool()
			ca, err := ioutil.ReadFile(*remoteCAPath)
			if err != nil {
				log.Fatalf("Failed to append %s to RootCAs: %v", *remoteCAPath, err)
			}
			cacertpool.AppendCertsFromPEM(ca)
			remoteTlsConfig.RootCAs = cacertpool
		} else {
			remoteTlsConfig.InsecureSkipVerify = true
		}
	}

	if err != nil {
		logger.Warn("Failed to open local port to listen: %s", err)
		os.Exit(1)
	}

	matcher := createMatcher(*match)
	replacer := createReplacer(*replace)

	if *veryverbose {
		*verbose = true
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Warn("Failed to accept connection '%s'", err)
			continue
		}
		connid++

		tlsConn, _ := conn.(*tls.Conn)
		tlsConn.Handshake()
		var p *proxy.Proxy
		if *unwrapTLS {
			logger.Info("Unwrapping TLS")
			p = proxy.NewTLSUnwrapped(conn, laddr, raddr, *remoteAddr, remoteTlsConfig)
		} else {
			p = proxy.New(conn, laddr, raddr)
		}

		p.Matcher = matcher
		p.Replacer = replacer

		p.OutputHex = *hex
		p.ProxyType = *proxyType
		p.Log = proxy.ColorLogger{
			Verbose:     *verbose,
			VeryVerbose: *veryverbose,
			Prefix:      fmt.Sprintf("Connection #%03d ", connid),
			Color:       *colors,
		}

		go p.Start()
	}
}

func createMatcher(match string) func([]byte) {
	if match == "" {
		return nil
	}
	re, err := regexp.Compile(match)
	if err != nil {
		logger.Warn("Invalid match regex: %s", err)
		return nil
	}

	logger.Info("Matching %s", re.String())
	return func(input []byte) {
		ms := re.FindAll(input, -1)
		for _, m := range ms {
			matchid++
			logger.Info("Match #%d: %s", matchid, string(m))
		}
	}
}

func createReplacer(replace string) func([]byte) []byte {
	if replace == "" {
		return nil
	}
	//split by / (TODO: allow slash escapes)
	parts := strings.Split(replace, "~")
	if len(parts) != 2 {
		logger.Warn("Invalid replace option")
		return nil
	}

	re, err := regexp.Compile(string(parts[0]))
	if err != nil {
		logger.Warn("Invalid replace regex: %s", err)
		return nil
	}

	repl := []byte(parts[1])

	logger.Info("Replacing %s with %s", re.String(), repl)
	return func(input []byte) []byte {
		return re.ReplaceAll(input, repl)
	}
}

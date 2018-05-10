package conn

import (
	"crypto/x509"
	"crypto/tls"
	"crypto/rsa"
	"fmt"
	"time"
	"math/big"
	crand "crypto/rand"
	"errors"
	"net"

	tpt "github.com/libp2p/go-libp2p-transport"
	ma "github.com/multiformats/go-multiaddr"
	iconn "github.com/libp2p/go-libp2p-interface-conn"
	pb "github.com/libp2p/go-libp2p-crypto/pb"
	"github.com/gogo/protobuf/proto"
	ci "github.com/libp2p/go-libp2p-crypto"
	"github.com/libp2p/go-libp2p-peer"
)

var PluggableCertToToKey = certificateToKey
var PluggableKeyToCert = keyToCertificate

func secureServerWithTLS(privateKey ci.PrivKey, connC iconn.Conn) (iconn.Conn, error) {
	connObj, ok := connC.(net.Conn)
	if !ok {
		return nil, fmt.Errorf("could not secure with tls")
	}
	cert := loadCerts(privateKey)
	conn := tls.Server(connObj, &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{cert},
		ClientAuth: tls.RequestClientCert})
	return doHandshake(conn, connC, privateKey)
}

func secureClientWithTLS(privateKey ci.PrivKey, connC iconn.Conn) (iconn.Conn, error) {
	connObj, ok := connC.(net.Conn)
	if !ok {
		return nil, fmt.Errorf("could not secure with tls")
	}
	cert := loadCerts(privateKey)
	conn := tls.Client(connObj, &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{cert},
		ClientAuth: tls.RequireAndVerifyClientCert})
	return doHandshake(conn, connC, privateKey)
}

func loadCerts(privateKey ci.PrivKey) tls.Certificate {
	// TODO: make this generic
	//privBytes, _ := ci.MarshalPrivateKey(privateKey)
	//pubBytes, _ := ci.MarshalPublicKey(privateKey.GetPublic())
	//pubBytes, _ := privateKey.GetPublic().Bytes()
	//privBytes, _ := privateKey.Bytes()
	cert, err := PluggableKeyToCert(privateKey)
	if err != nil {
		log.Fatal(err)
	}

	return *cert
}

func doHandshake(conn *tls.Conn, insecure iconn.Conn, priv ci.PrivKey) (iconn.Conn, error) {
	tlsConn := &tlsConn{secure: conn, insecure: insecure, localPrivateKey:priv}
	err := conn.Handshake()
	log.Info("after tls handshake", err)

	if len(conn.ConnectionState().PeerCertificates) < 1 {
		log.Error("no keys")
		return nil, fmt.Errorf("no public key for peer")
	}

	pubKey, err := PluggableCertToToKey(conn.ConnectionState().PeerCertificates[0])
	if err != nil {
		log.Error("permanentPubKey not valid", err)
		return nil, err
	}

	tlsConn.peerPubKey = pubKey
	return tlsConn, err
}

type tlsConn struct {
	secure          net.Conn
	insecure        iconn.Conn
	peerPubKey      ci.PubKey
	localPrivateKey ci.PrivKey
}

func (conn *tlsConn) Write(p []byte) (n int, err error) {
	return conn.secure.Write(p)
}

func (conn *tlsConn) Read(p []byte) (n int, err error) {
	return conn.secure.Read(p)
}

func (conn *tlsConn) LocalPeer() peer.ID {
	return conn.insecure.LocalPeer()
}

func (conn *tlsConn) LocalPrivateKey() ci.PrivKey {
	return conn.localPrivateKey
}

func (conn *tlsConn) LocalMultiaddr() ma.Multiaddr {
	return conn.insecure.LocalMultiaddr()
}

// RemotePeer ID, PublicKey, and Address
func (conn *tlsConn) RemotePeer() peer.ID {
	id, _ := peer.IDFromPublicKey(conn.RemotePublicKey())
	return id
}

func (conn *tlsConn) RemotePublicKey() ci.PubKey {
	return conn.peerPubKey
}

func (conn *tlsConn) RemoteMultiaddr() ma.Multiaddr {
	return conn.insecure.RemoteMultiaddr()
}

// ID is an identifier unique to this connection.
func (conn *tlsConn) ID() string {
	return iconn.ID(conn)
}

func (conn *tlsConn) LocalAddr() net.Addr {
	return conn.secure.LocalAddr()
}

func (conn *tlsConn) RemoteAddr() net.Addr {
	return conn.secure.RemoteAddr()
}

func (conn *tlsConn) SetDeadline(t time.Time) error {
	return conn.insecure.SetDeadline(t)
}

func (conn *tlsConn) SetReadDeadline(t time.Time) error {
	return conn.insecure.SetReadDeadline(t)
}

func (conn *tlsConn) SetWriteDeadline(t time.Time) error {
	return conn.insecure.SetWriteDeadline(t)
}

func (conn *tlsConn) Transport() tpt.Transport {
	return conn.insecure.Transport()
}

func (conn *tlsConn) Close() error {
	return conn.secure.Close()
}

// credit : https://github.com/libp2p/go-libp2p-conn/pull/27/files
func keyToCertificate(sk ci.PrivKey) (*tls.Certificate, error) {
	tmpl := &x509.Certificate{}
	tmpl.NotAfter = time.Now().Add(24 * time.Hour)
	tmpl.NotBefore = time.Now().Add(-24 * time.Hour)
	tmpl.SerialNumber, _ = crand.Int(crand.Reader, big.NewInt(1<<62))
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	p, _ := peer.IDFromPrivateKey(sk)
	tmpl.Subject.CommonName = p.Pretty()

	var publicKey, privateKey interface{}
	keyBytes, err := sk.Bytes()
	if err != nil {
		return nil, err
	}
	pbmes := new(pb.PrivateKey)
	if err := proto.Unmarshal(keyBytes, pbmes); err != nil {
		return nil, err
	}

	switch pbmes.GetType() {
	case pb.KeyType_RSA:
		tmpl.SignatureAlgorithm = x509.SHA256WithRSA
		k, err := x509.ParsePKCS1PrivateKey(pbmes.GetData())
		if err != nil {
			return nil, err
		}
		publicKey = &k.PublicKey
		privateKey = k
	default:
		return nil, errors.New("unsupported key type for TLS")
	}
	cert, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{cert},
		PrivateKey:  privateKey,
	}, nil
}

func certificateToKey(cert *x509.Certificate) (ci.PubKey, error) {
	switch pk := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		der, err := x509.MarshalPKIXPublicKey(pk)
		if err != nil {
			return nil, err
		}
		k, err := ci.UnmarshalRsaPublicKey(der)
		if err != nil {
			return nil, err
		}
		return k, nil
	default:
		return nil, errors.New("unsupported certificate key type")
	}
}

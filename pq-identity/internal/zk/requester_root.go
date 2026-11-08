package zk

import (
	"crypto/x509"

	"a2aid/internal/verifier"
)

func setRoot(r *verifier.Requester, pool interface{}) {
	if p, ok := pool.(*x509.CertPool); ok {
		r.RootCAs = p
	}
}

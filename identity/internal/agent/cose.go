package agent

import (
	"io"

	"github.com/google/go-tpm/tpm2/transport"
	cose "github.com/veraison/go-cose"

	"a2aid/internal/tpmsig"
)

// coseSignerFn adapts a closure to cose.Signer (ES256, raw r||s).
type coseSignerFn func(content []byte) ([]byte, error)

func (f coseSignerFn) Algorithm() cose.Algorithm                        { return cose.AlgorithmES256 }
func (f coseSignerFn) Sign(_ io.Reader, content []byte) ([]byte, error) { return f(content) }

func connTransport(c *tpmsig.Conn) transport.TPM { return c.Transport() }

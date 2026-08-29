package appstore

import (
	"context"

	"github.com/londek/ipadecrypt/internal/sap"
)

// SAPConfig is the signing configuration Apple returns in the bag. The login
// request body must be signed with a machine identity established against the
// setup/certificate endpoints before it is accepted.
type SAPConfig struct {
	AuthEndpoint   string
	SetupURL       string
	CertificateURL string
	Version        uint32
}

// ActionSigner signs App Store request bodies with a virtual machine identity.
type ActionSigner interface {
	Sign(data []byte) ([]byte, error)
	Close() error
}

// ActionSignerFactory builds a signer from the bag's SAP config and the caller's
// machine id (the MAC address bytes).
type ActionSignerFactory func(config SAPConfig, machineID []byte) (ActionSigner, error)

// defaultActionSignerFactory is the built-in SAP signer backed by Apple's
// FairPlay runtime.
func defaultActionSignerFactory(config SAPConfig, machineID []byte) (ActionSigner, error) {
	return sap.NewSigner(context.Background(), sap.Config{
		SetupURL:       config.SetupURL,
		CertificateURL: config.CertificateURL,
		Version:        config.Version,
		HardwareID:     machineID,
	})
}

package appstore

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	cookiejar "github.com/juju/persistent-cookiejar"
)

type Client struct {
	jar                 *cookiejar.Jar
	http                *http.Client
	actionSignerFactory ActionSignerFactory
	mac                 string
}

// New creates an App Store client. When fixedMAC is supplied, it is used as
// the App Store machine identity instead of discovering a host interface.
// The supplied address must be a six-byte MAC address.
func New(cookiesFile string, fixedMAC ...string) (*Client, error) {
	if len(fixedMAC) > 1 {
		return nil, errors.New("app store: at most one fixed MAC address may be supplied")
	}

	mac := ""
	if len(fixedMAC) == 1 && fixedMAC[0] != "" {
		var err error
		mac, err = NormalizeMACAddress(fixedMAC[0])
		if err != nil {
			return nil, fmt.Errorf("app store: invalid fixed MAC address: %w", err)
		}
	}

	jar, err := cookiejar.New(&cookiejar.Options{Filename: cookiesFile})
	if err != nil {
		return nil, err
	}

	hc := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.Referer() == authURL {
				return http.ErrUseLastResponse
			}

			return nil
		},
	}

	return &Client{jar: jar, http: hc, actionSignerFactory: defaultActionSignerFactory, mac: mac}, nil
}

// guid returns the Configurator-shaped GUID: uppercase MAC address, no colons.
func (c *Client) guid() (string, error) {
	mac, err := c.macAddress()
	if err != nil {
		return "", err
	}

	return strings.ReplaceAll(strings.ToUpper(mac), ":", ""), nil
}

func (c *Client) macAddress() (string, error) {
	if c.mac != "" {
		return c.mac, nil
	}

	return hostMACAddress()
}

func hostMACAddress() (string, error) {
	if iface, err := net.InterfaceByName("en0"); err == nil && iface.HardwareAddr != nil {
		if s := iface.HardwareAddr.String(); s != "" {
			return s, nil
		}
	}

	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, ni := range ifs {
		if s := ni.HardwareAddr.String(); s != "" {
			return s, nil
		}
	}

	return "", errors.New("no network interface with a MAC address")
}

// NormalizeMACAddress validates a fixed App Store identity and returns its
// canonical lower-case, colon-separated representation.
func NormalizeMACAddress(value string) (string, error) {
	hardwareAddress, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil {
		return "", err
	}
	if len(hardwareAddress) != 6 {
		return "", errors.New("must be a six-byte MAC address")
	}

	return hardwareAddress.String(), nil
}

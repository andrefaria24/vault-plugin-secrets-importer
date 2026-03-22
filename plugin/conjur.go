package plugin

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/conjur-api-go/conjurapi/authn"
)

type conjurProviderFactory func(*conjurConfig) (conjurProvider, error)

type conjurConfig struct {
	ApplianceURL string
	Account      string
	Login        string
	APIKey       string
	SSLCert      string
	SSLCertPath  string
	AuthnType    string
	ServiceID    string
}

type conjurRequest struct {
	VariableID string
	ParseJSON  bool
	RawField   string
}

type conjurProvider interface {
	ReadSecret(context.Context, *conjurRequest) (*externalSecret, error)
}

type conjurClient struct {
	client *conjurapi.Client
	config *conjurConfig
}

func newConjurProvider(cfg *conjurConfig) (conjurProvider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("conjur configuration is missing")
	}
	if strings.TrimSpace(cfg.ApplianceURL) == "" {
		return nil, fmt.Errorf("conjur appliance_url is required")
	}
	if strings.TrimSpace(cfg.Account) == "" {
		return nil, fmt.Errorf("conjur account is required")
	}
	if strings.TrimSpace(cfg.Login) == "" {
		return nil, fmt.Errorf("conjur login is required")
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, fmt.Errorf("conjur api_key is required")
	}

	conjurCfg := conjurapi.Config{
		ApplianceURL: strings.TrimSpace(cfg.ApplianceURL),
		Account:      strings.TrimSpace(cfg.Account),
		SSLCert:      cfg.SSLCert,
		SSLCertPath:  strings.TrimSpace(cfg.SSLCertPath),
		AuthnType:    strings.TrimSpace(cfg.AuthnType),
		ServiceID:    strings.TrimSpace(cfg.ServiceID),
	}

	client, err := conjurapi.NewClientFromKey(conjurCfg, authn.LoginPair{
		Login:  strings.TrimSpace(cfg.Login),
		APIKey: strings.TrimSpace(cfg.APIKey),
	})
	if err != nil {
		return nil, fmt.Errorf("create Conjur client: %w", err)
	}

	return &conjurClient{
		client: client,
		config: cfg,
	}, nil
}

func (c *conjurClient) ReadSecret(ctx context.Context, req *conjurRequest) (*externalSecret, error) {
	if req == nil {
		return nil, fmt.Errorf("conjur request is missing")
	}
	if strings.TrimSpace(req.VariableID) == "" {
		return nil, fmt.Errorf("variable_id is required")
	}

	_ = ctx

	rawValue, err := c.client.RetrieveSecret(req.VariableID)
	if err != nil {
		return nil, fmt.Errorf("read Conjur variable %q: %w", req.VariableID, err)
	}

	var data map[string]interface{}
	if utf8.Valid(rawValue) {
		data, err = normalizeExternalSecret(string(rawValue), nil, req.ParseJSON, req.RawField)
	} else {
		data, err = normalizeExternalSecret("", rawValue, req.ParseJSON, req.RawField)
	}
	if err != nil {
		return nil, err
	}

	return &externalSecret{
		SourceType: "cyberark-conjur",
		SourceID:   req.VariableID,
		Data:       data,
		Metadata: map[string]interface{}{
			"provider":      "cyberark-conjur",
			"appliance_url": strings.TrimSpace(c.config.ApplianceURL),
			"account":       strings.TrimSpace(c.config.Account),
			"login":         strings.TrimSpace(c.config.Login),
			"variable_id":   req.VariableID,
			"authn_type":    strings.TrimSpace(c.config.AuthnType),
			"service_id":    strings.TrimSpace(c.config.ServiceID),
		},
	}, nil
}

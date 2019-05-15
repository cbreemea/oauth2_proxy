package providers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pusher/oauth2_proxy/api"
	"github.com/pusher/oauth2_proxy/logger"
	"golang.org/x/oauth2/jws"
)

// AzureV2Provider represents an AzureV2 based Identity Provider
type AzureV2Provider struct {
	*ProviderData
	Tenant string
}

// NewAzureV2Provider initiates a new AzureV2Provider
func NewAzureV2Provider(p *ProviderData) *AzureV2Provider {
	p.ProviderName = "azure.v2"

	if p.ProfileURL == nil || p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{
			Scheme: "https",
			Host:   "https://graph.microsoft.com",
			Path:   "/me",
		}
	}

	p.ProtectedResource = nil

	if p.Scope == "" {
		p.Scope = "openid"
	}
	return &AzureV2Provider{ProviderData: p}
}

// Configure defaults the AzureV2Provider configuration options
func (p *AzureV2Provider) Configure(tenant string) {
	p.Tenant = tenant
	if tenant == "" {
		p.Tenant = "common"
	}

	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "login.microsoftonline.com",
			Path:   "/" + p.Tenant + "/oauth2/v2.0/authorize"}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "login.microsoftonline.com",
			Path:   "/" + p.Tenant + "/oauth2/v2.0/token"}
	}
}

func getAzureV2Header(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}

// GetEmailAddress returns the Account email address
func (p *AzureV2Provider) GetEmailAddress(s *SessionState) (string, error) {
	fmt.Printf("%+v\n", *s)

	claimSet, err := jws.Decode(s.AccessToken)
	if err != nil {
		panic(err)
	}

	var email string

	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header = getAzureV2Header(s.AccessToken)

	json, err := api.Request(req)

	if err != nil {
		return "", err
	}

	email, err = getEmailFromJSON(json)

	if err == nil && email != "" {
		return email, err
	}

	email, err = json.Get("userPrincipalName").String()

	if err != nil {
		logger.Printf("failed making request %s", err)
		return "", err
	}

	if email == "" {
		logger.Printf("failed to get email address")
		return "", err
	}

	return email, err
}

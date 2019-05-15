package providers

import (
	"fmt"
	"net/http"
	"net/url"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pusher/oauth2_proxy/logger"
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
func (p *AzureV2Provider) GetEmailAddress(s *SessionState) (email string, err error) {

	tokenString := s.AccessToken
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("<YOUR VERIFICATION KEY>"), nil
	})

	for key, val := range claims {
		if key == "email" {
			email = val.(string)
		}
	}

	if email == "" {
		logger.Printf("failed to get email address")
		return "", err
	}

	return email, err
}

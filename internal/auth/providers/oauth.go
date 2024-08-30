package providers

import (
	"echo-server/internal/auth"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt"
)

type OAuthProvider struct {
	Id                string
	Name              string
	Issuer            string
	Type              string
	Image             string
	Scopes            []string
	Authorization     string
	Token             string
	UserInfo          string
	ClientId          string
	ClientSecret      string
	AllowEmailLinking bool
}

// GetId implements auth.Provider.
func (p OAuthProvider) GetId() string {
	return p.Id
}

// GetType implements auth.Provider.
func (p OAuthProvider) GetType() string {
	return p.Type
}

// GetPublicData implements auth.Provider.
func (p OAuthProvider) GetPublicData() auth.ProviderData {
	return auth.ProviderData{
		Id:     p.Id,
		Name:   p.Name,
		Issuer: p.Issuer,
		Type:   p.Type,
		Image:  p.Image,
	}
}

// GetRedirectURL implements auth.Provider.
func (p OAuthProvider) GetRedirectURL(base string) string {
	authUrl := p.Authorization
	clientId := p.ClientId
	scopes := strings.Join(p.Scopes, " ")

	state := auth.GenerateVerificationToken(16)

	query := url.Values{}
	query.Set("client_id", clientId)
	query.Set("redirect_uri", base)
	query.Set("response_type", "code")
	query.Set("scope", scopes)
	query.Set("state", state)

	return fmt.Sprintf("%s?%s", authUrl, query.Encode())
}

// HandleCallback implements auth.Provider.
func (p OAuthProvider) HandleCallback(url *url.URL) (auth.Profile, auth.TokenSet, error) {
	// state := url.Query().Get("state")
	code := url.Query().Get("code")

	fail := func(err error) (auth.Profile, auth.TokenSet, error) {
		return auth.Profile{}, auth.TokenSet{}, err
	}

	// if auth.VerifyVerificationToken(state) {
	// 	return fail(fmt.Errorf("invalid state"))
	// }

	tokenSet, err := p.Exchange(code)
	if err != nil {
		return fail(err)
	}

	profile, err := p.GetProfile(&tokenSet)
	if err != nil {
		return fail(err)
	}

	if p.AllowEmailLinking {
		profile.EmailVerified = true
	}

	return profile, tokenSet, nil
}

func (p OAuthProvider) Exchange(code string) (auth.TokenSet, error) {
	query := url.Values{}
	query.Set("code", code)
	query.Set("client_id", p.ClientId)
	query.Set("client_secret", p.ClientSecret)
	query.Set("redirect_uri", "http://localhost:8080/auth/callback/"+p.Id)
	query.Set("grant_type", "authorization_code")

	fail := func(err error) (auth.TokenSet, error) {
		return auth.TokenSet{}, err
	}

	req, err := http.NewRequest("POST", p.Token, strings.NewReader(query.Encode()))
	if err != nil {
		return fail(err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fail(err)
	}
	defer res.Body.Close()

	var tokenSet auth.TokenSet
	if err := json.NewDecoder(res.Body).Decode(&tokenSet); err != nil {
		return fail(err)
	}

	return tokenSet, nil
}

func (p OAuthProvider) GetProfile(token *auth.TokenSet) (auth.Profile, error) {
	fail := func(err error) (auth.Profile, error) {
		return auth.Profile{}, err
	}

	if token.IdToken == "" {
		return fail(fmt.Errorf("missing id_token"))
	}

	parsed, _, err := new(jwt.Parser).ParseUnverified(token.IdToken, jwt.MapClaims{})
	if err != nil {
		return fail(err)
	}

	claims := parsed.Claims.(jwt.MapClaims)

	var profile auth.Profile

	if claims["sub"] != nil {
		profile.Id = claims["sub"].(string)
		profile.Sub = claims["sub"].(string)
	}
	if claims["email"] != nil {
		profile.Email = claims["email"].(string)
	}
	if claims["name"] != nil {
		profile.Name = claims["name"].(string)
	}
	if claims["given_name"] != nil {
		profile.GivenName = claims["given_name"].(string)
	}
	if claims["family_name"] != nil {
		profile.FamilyName = claims["family_name"].(string)
	}
	if claims["middle_name"] != nil {
		profile.MiddleName = claims["middle_name"].(string)
	}
	if claims["nickname"] != nil {
		profile.Nickname = claims["nickname"].(string)
	}
	if claims["profile"] != nil {
		profile.Profile = claims["profile"].(string)
	}
	if claims["picture"] != nil {
		profile.Picture = claims["picture"].(string)
	}
	if claims["website"] != nil {
		profile.Website = claims["website"].(string)
	}
	if claims["email_verified"] != nil {
		profile.EmailVerified = claims["email_verified"].(bool)
	}
	if claims["gender"] != nil {
		profile.Gender = claims["gender"].(string)
	}
	if claims["birthdate"] != nil {
		profile.Birthdate = claims["birthdate"].(string)
	}
	if claims["zoneinfo"] != nil {
		profile.Zoneinfo = claims["zoneinfo"].(string)
	}
	if claims["locale"] != nil {
		profile.Locale = claims["locale"].(string)
	}
	if claims["phone_number"] != nil {
		profile.PhoneNumber = claims["phone_number"].(string)
	}
	if claims["address"] != nil {
		profile.Address = claims["address"].(string)
	}
	if claims["updated_at"] != nil {
		profile.UpdatedAt = claims["updated_at"].(string)
	}

	return profile, nil
}

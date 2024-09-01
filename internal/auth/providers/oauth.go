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

	state := auth.GenerateHMACToken(16)

	fmt.Println(state, "")

	query := url.Values{}
	query.Set("client_id", clientId)
	query.Set("redirect_uri", base)
	query.Set("response_type", "code")
	query.Set("scope", scopes)
	query.Set("state", state)

	return fmt.Sprintf("%s?%s", authUrl, query.Encode())
}

// HandleCallback implements auth.Provider.
func (p OAuthProvider) HandleCallback(req *http.Request) (auth.Profile, auth.TokenSet, error) {
	state := req.URL.Query().Get("state")
	code := req.URL.Query().Get("code")
	fmt.Println(state, code)

	fail := func(err error) (auth.Profile, auth.TokenSet, error) {
		return auth.Profile{}, auth.TokenSet{}, err
	}

	if !auth.VerifyHMACToken(state) {
		return fail(fmt.Errorf("invalid state"))
	}

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

	mapClaimsToProfile := func(key string, target *string) {
		if val, ok := claims[key]; ok {
			*target = val.(string)
		}
	}

	var profile auth.Profile
	mapClaimsToProfile("sub", &profile.Id)
	mapClaimsToProfile("sub", &profile.Sub)
	mapClaimsToProfile("email", &profile.Email)
	mapClaimsToProfile("name", &profile.Name)
	mapClaimsToProfile("given_name", &profile.GivenName)
	mapClaimsToProfile("family_name", &profile.FamilyName)
	mapClaimsToProfile("middle_name", &profile.MiddleName)
	mapClaimsToProfile("nickname", &profile.Nickname)
	mapClaimsToProfile("profile", &profile.Profile)
	mapClaimsToProfile("picture", &profile.Picture)
	mapClaimsToProfile("website", &profile.Website)
	mapClaimsToProfile("gender", &profile.Gender)
	mapClaimsToProfile("birthdate", &profile.Birthdate)
	mapClaimsToProfile("zoneinfo", &profile.Zoneinfo)
	mapClaimsToProfile("locale", &profile.Locale)
	mapClaimsToProfile("phone_number", &profile.PhoneNumber)
	mapClaimsToProfile("address", &profile.Address)
	mapClaimsToProfile("updated_at", &profile.UpdatedAt)

	return profile, nil
}

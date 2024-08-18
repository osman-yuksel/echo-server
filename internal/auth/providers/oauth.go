package providers

import (
	"echo-server/internal/auth"
	"echo-server/internal/database"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt"
)

type TokenSet struct {
	AcessToken   string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int    `json:"expires_at"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

type IdToken struct {
	Aud           string `json:"aud"`
	Exp           int    `json:"exp"`
	Iat           int    `json:"iat"`
	Iss           string `json:"iss"`
	Sub           string `json:"sub"`
	AtHash        string `json:"at_hash"`
	Azp           string `json:"azp"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	FamilName     string `json:"family_name"`
	GivenName     string `json:"given_name"`
	Picture       string `json:"picture"`
	Profile       string `json:"profile"`
	Locale        string `json:"locale"`
	Nonce         string `json:"nonce"`
}

type OAuthProvider struct {
	Id            string
	Name          string
	Issuer        string
	Type          string
	Image         string
	Scopes        []string
	Authorization string
	Token         string
	UserInfo      string
	ClientId      string
	ClientSecret  string
}

type UserInfo struct {
	Id        string `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	FirstName string `json:"given_name"`
	LastName  string `json:"family_name"`
	Link      string `json:"link"`
	Picture   string `json:"picture"`
	Token     string `json:"token"`
}

// GetId implements auth.Provider.
func (p OAuthProvider) GetId() string {
	return p.Id
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
func (p OAuthProvider) GetRedirectURL() string {
	authUrl := p.Authorization
	clientId := p.ClientId
	redirect := "http://localhost:8080/auth/callback/" + p.Id
	scopes := strings.Join(p.Scopes, " ")
	state := auth.GenerateVerificationKey()

	query := url.Values{}
	query.Set("client_id", clientId)
	query.Set("redirect_uri", redirect)
	query.Set("response_type", "code")
	query.Set("scope", scopes)
	query.Set("state", state)

	return fmt.Sprintf("%s?%s", authUrl, query.Encode())
}

// HandleCallback implements auth.Provider.
func (p OAuthProvider) HandleCallback(url *url.URL) (database.Account, database.User, error) {
	// state := url.Query().Get("state")
	code := url.Query().Get("code")

	// if auth.ValidateVerificationKey(state) {
	// 	// return database.Account{}, database.User{}, fmt.Errorf("invalid state")
	// }

	tokenSet, err := p.Exchange(code)
	if err != nil {
		return database.Account{}, database.User{}, err
	}

	user, err := p.GetUserInfo(&tokenSet)
	if err != nil {
		return database.Account{}, database.User{}, err
	}

	return database.Account{
			Type:              p.Type,
			Provider:          p.Id,
			ProviderAccountId: user.Id,
			RefreshToken:      tokenSet.RefreshToken,
			AccessToken:       tokenSet.AcessToken,
			ExpiresAt:         int64(tokenSet.ExpiresAt),
			IdToken:           tokenSet.IDToken,
			Scope:             tokenSet.Scope,
			TokenType:         tokenSet.TokenType,
		}, database.User{
			Name:          user.Name,
			Email:         user.Email,
			EmailVerified: true,
			Image:         user.Picture,
		}, nil
}

func (p OAuthProvider) Exchange(code string) (TokenSet, error) {
	query := url.Values{}
	query.Set("code", code)
	query.Set("client_id", p.ClientId)
	query.Set("client_secret", p.ClientSecret)
	query.Set("redirect_uri", "http://localhost:8080/auth/callback/"+p.Id)
	query.Set("grant_type", "authorization_code")

	req, err := http.NewRequest("POST", p.Token, strings.NewReader(query.Encode()))
	if err != nil {
		return TokenSet{}, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return TokenSet{}, err
	}
	defer res.Body.Close()

	var tokenSet TokenSet
	if err := json.NewDecoder(res.Body).Decode(&tokenSet); err != nil {
		return TokenSet{}, err
	}

	return tokenSet, nil
}

func (p OAuthProvider) GetUserInfo(token *TokenSet) (UserInfo, error) {
	if token.IDToken == "" {
		return UserInfo{}, fmt.Errorf("missing id_token")
	}

	parsed, _, err := new(jwt.Parser).ParseUnverified(token.IDToken, jwt.MapClaims{})
	if err != nil {
		return UserInfo{}, err
	}

	claims := parsed.Claims.(jwt.MapClaims)
	return UserInfo{
		Id:        claims["sub"].(string),
		Email:     claims["email"].(string),
		Name:      claims["name"].(string),
		FirstName: claims["given_name"].(string),
		LastName:  claims["family_name"].(string),
		Picture:   claims["picture"].(string),
		Token:     token.AcessToken,
	}, nil
}

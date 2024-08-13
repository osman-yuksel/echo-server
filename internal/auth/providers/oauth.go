package providers

import (
	"crypto/sha256"
	"echo-server/internal/auth"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/golang-jwt/jwt"
)

var AUTH_SECRET = os.Getenv("AUTH_SECRET")

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
	state := generateState()

	query := url.Values{}
	query.Set("client_id", clientId)
	query.Set("redirect_uri", redirect)
	query.Set("response_type", "code")
	query.Set("scope", scopes)
	query.Set("state", state)

	return fmt.Sprintf("%s?%s", authUrl, query.Encode())
}

// HandleCallback implements auth.Provider.
func (p OAuthProvider) HandleCallback(url *url.URL) (auth.Account, error) {
	state := url.Query().Get("state")
	code := url.Query().Get("code")

	if !p.validateState(state) {
		return auth.Account{}, fmt.Errorf("invalid state")
	}

	tokenSet, err := p.Exchange(code)
	if err != nil {
		return auth.Account{}, err
	}

	user, err := p.GetUserInfo(&tokenSet)
	if err != nil {
		return auth.Account{}, err
	}

	return auth.Account{
		Id:    user.Id,
		Email: user.Email,
		Name:  user.Name,
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
		Id:    claims["sub"].(string),
		Email: claims["email"].(string),
		Name:  claims["name"].(string),
	}, nil
}

func generateState() string {
	s := randomString(16)

	h := sha256.New()
	h.Write([]byte(s + AUTH_SECRET))
	sha1_hash := hex.EncodeToString(h.Sum(nil))[:32]

	return s + "|" + sha1_hash
}

func (p OAuthProvider) validateState(state string) bool {
	parts := strings.Split(state, "|")
	if len(parts) != 2 {
		return false
	}

	h := sha256.New()
	h.Write([]byte(parts[0] + AUTH_SECRET))
	sha1_hash := hex.EncodeToString(h.Sum(nil))[:32]
	return parts[1] == sha1_hash
}

const letterBytes = "abcdefghijklmnopqrstuvwxyz"

func randomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}

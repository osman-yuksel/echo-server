package auth

type Profile struct {
	Id            string `json:"id,omitempty"`
	Sub           string `json:"sub,omitempty"`
	Name          string `json:"name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	MiddleName    string `json:"middle_name,omitempty"`
	Nickname      string `json:"nickname,omitempty"`
	Profile       string `json:"profile,omitempty"`
	Picture       string `json:"picture,omitempty"`
	Website       string `json:"website,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Gender        string `json:"gender,omitempty"`
	Birthdate     string `json:"birthdate,omitempty"`
	Zoneinfo      string `json:"zoneinfo,omitempty"`
	Locale        string `json:"locale,omitempty"`
	PhoneNumber   string `json:"phone_number,omitempty"`
	Address       string `json:"address,omitempty"`
	UpdatedAt     string `json:"updated_at,omitempty"`
}

type IdToken struct {
	Aud           string `json:"aud,omitempty"`
	Exp           int    `json:"exp,omitempty"`
	Iat           int    `json:"iat,omitempty"`
	Iss           string `json:"iss,omitempty"`
	Sub           string `json:"sub,omitempty"`
	AtHash        string `json:"at_hash,omitempty"`
	Azp           string `json:"azp,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	FamilName     string `json:"family_name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	Picture       string `json:"picture,omitempty"`
	Profile       string `json:"profile,omitempty"`
	Locale        string `json:"locale,omitempty"`
	Nonce         string `json:"nonce,omitempty"`
}

type TokenSet struct {
	AccessToken  string `json:"access_token"`
	IdToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int    `json:"expires_at"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

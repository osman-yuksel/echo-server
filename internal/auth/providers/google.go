package providers

import "os"

func Google() OAuthProvider {
	return OAuthProvider{
		Id:            "google",
		Name:          "Google",
		Issuer:        "https://accounts.google.com",
		Type:          "oauth",
		Image:         "https://lh3.googleusercontent.com/COxitqgJr1sJnIDe8-jiKhxDx1FrYbtRHKJ9z_hELisAlapwE9LUPh6fcXIfb5vwpbMl4xl9H9TRFPc5NOO8Sb3VSgIBrfRYvW6cUA",
		Scopes:        []string{"openid", "profile", "email"},
		Authorization: "https://accounts.google.com/o/oauth2/v2/auth",
		Token:         "https://oauth2.googleapis.com/token",
		UserInfo:      "https://openidconnect.googleapis.com/v1/userinfo",
		ClientId:      os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret:  os.Getenv("GOOGLE_CLIENT_SECRET"),
	}
}

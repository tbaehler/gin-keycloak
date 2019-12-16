package ginkeycloak

type KeyCloakToken struct {
	Jti string `json:"jti"`
	Exp int64  `json:"exp"`
	Nbf int64  `json:"nbf"`
	Iat int64  `json:"iat"`
	Iss string `json:"iss"`
	//Aud               []string               `json:"aud"`
	Sub               string                 `json:"sub"`
	Typ               string                 `json:"typ"`
	Azp               string                 `json:"azp"`
	Nonce             string                 `json:"nonce"`
	AuthTime          int64                  `json:"auth_time"`
	SessionState      string                 `json:"session_state"`
	Acr               string                 `json:"acr"`
	ClientSession     string                 `json:"client_session"`
	AllowedOrigins    []string               `json:"allowed-origins"`
	ResourceAccess    map[string]ServiceRole `json:"resource_access"`
	Name              string                 `json:"name"`
	PreferredUsername string                 `json:"preferred_username"`
	GivenName         string                 `json:"given_name"`
	FamilyName        string                 `json:"family_name"`
	Email             string                 `json:"email"`
}

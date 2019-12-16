package ginkeycloak

type Certs struct {
	Keys []KeyEntry `json:"keys"`
}

type KeyEntry struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

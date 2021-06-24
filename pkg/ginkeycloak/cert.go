package ginkeycloak

type Certs struct {
	Keys []KeyEntry `json:"keys"`
}

type KeyEntry struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	Alg string   `json:"alg"`
	Use string   `json:"use"`
	Crv string   `json:"crv"`
	X   string   `json:"x"`
	Y   string   `json:"y"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5C []string `json:"x5c"`
}

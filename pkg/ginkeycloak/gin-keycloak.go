package ginkeycloak

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
	"github.com/patrickmn/go-cache"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// VarianceTimer controls the max runtime of Auth() and AuthChain() middleware
var VarianceTimer time.Duration = 30000 * time.Millisecond
var Transport = http.Transport{}
var publicKeyCache = cache.New(8*time.Hour, 8*time.Hour)

// TokenContainer stores all relevant token information
type TokenContainer struct {
	Token         *oauth2.Token
	KeyCloakToken *KeyCloakToken
}

type ServiceRole struct {
	Roles []string `json:"roles"`
}

func extractToken(r *http.Request) (*oauth2.Token, error) {
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		return nil, errors.New("No authorization header")
	}

	th := strings.Split(hdr, " ")
	if len(th) != 2 {
		return nil, errors.New("Incomplete authorization header")
	}

	return &oauth2.Token{AccessToken: th[1], TokenType: th[0]}, nil
}

func GetTokenContainer(token *oauth2.Token, config KeycloakConfig) (*TokenContainer, error) {

	keyCloakToken, err := decodeToken(token, config)
	if err != nil {
		return nil, err
	}

	return &TokenContainer{
		Token: &oauth2.Token{
			AccessToken: token.AccessToken,
			TokenType:   token.TokenType,
		},
		KeyCloakToken: keyCloakToken,
	}, nil
}

func getPublicKey(keyId string, config KeycloakConfig) (string, string, error) {
	keyEntry, exists := publicKeyCache.Get(keyId)
	if !exists {
		url := config.Url + "/auth/realms/" + config.Realm + "/protocol/openid-connect/certs"

		resp, err := http.Get(url)
		if err != nil {
			return "", "", err
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)

		var certs Certs
		err = json.Unmarshal(body, &certs)
		if err != nil {
			return "", "", err
		}

		keyEntry = certs
		publicKeyCache.Set(keyId, keyEntry, cache.DefaultExpiration)
	}

	for _, keyIdFromServer := range keyEntry.(Certs).Keys {
		if keyIdFromServer.Kid == keyId {
			return keyIdFromServer.N, keyIdFromServer.E, nil
		}
	}

	return "", "", errors.New("no key found")
}

func decodeToken(token *oauth2.Token, config KeycloakConfig) (*KeyCloakToken, error) {
	keyCloakToken := KeyCloakToken{}
	var err error
	parsedJWT, err := jwt.ParseSigned(token.AccessToken)
	if err != nil {
		glog.Errorf("[Gin-OAuth] jwt not decodable: %s", err)
		return nil, err
	}
	n, e, err := getPublicKey(parsedJWT.Headers[0].KeyID, config)
	if err != nil {
		glog.Errorf("Failed to get publickey %v", err)
		return nil, err
	}
	num, _ := base64.RawURLEncoding.DecodeString(n)

	bigN := new(big.Int)
	bigN.SetBytes(num)
	num, _ = base64.RawURLEncoding.DecodeString(e)
	bigE := new(big.Int)
	bigE.SetBytes(num)
	key := rsa.PublicKey{bigN, int(bigE.Int64())}

	err = parsedJWT.Claims(&key, &keyCloakToken)
	if err != nil {
		glog.Errorf("Failed to get claims JWT:%+v", err)
		return nil, err
	}
	return &keyCloakToken, nil
}

func isExpired(token *KeyCloakToken) bool {
	if token.Exp == 0 {
		return false
	}
	now := time.Now()
	fromUnixTimestamp := time.Unix(token.Exp, 0)
	return now.After(fromUnixTimestamp)
}

func getTokenContainer(ctx *gin.Context, config KeycloakConfig) (*TokenContainer, bool) {
	var oauthToken *oauth2.Token
	var tc *TokenContainer
	var err error

	if oauthToken, err = extractToken(ctx.Request); err != nil {
		glog.Errorf("[Gin-OAuth] Can not extract oauth2.Token, caused by: %s", err)
		return nil, false
	}
	if !oauthToken.Valid() {
		glog.Infof("[Gin-OAuth] Invalid Token - nil or expired")
		return nil, false
	}

	if tc, err = GetTokenContainer(oauthToken, config); err != nil {
		glog.Errorf("[Gin-OAuth] Can not extract TokenContainer, caused by: %s", err)
		return nil, false
	}

	if isExpired(tc.KeyCloakToken) {
		glog.Errorf("[Gin-OAuth] Keycloak Token has expired")
		return nil, false
	}

	return tc, true
}

func (t *TokenContainer) Valid() bool {
	if t.Token == nil {
		return false
	}
	return t.Token.Valid()
}

type KeycloakConfig struct {
	Url   string
	Realm string
}

func Auth(accessCheckFunction AccessCheckFunction, endpoints KeycloakConfig) gin.HandlerFunc {
	return authChain(endpoints, accessCheckFunction)
}

func authChain(config KeycloakConfig, accessCheckFunctions ...AccessCheckFunction) gin.HandlerFunc {
	// middleware
	return func(ctx *gin.Context) {
		t := time.Now()
		varianceControl := make(chan bool, 1)

		go func() {
			tokenContainer, ok := getTokenContainer(ctx, config)
			if !ok {
				ctx.AbortWithError(http.StatusUnauthorized, errors.New("No token in context"))
				varianceControl <- false
				return
			}

			if !tokenContainer.Valid() {
				ctx.AbortWithError(http.StatusUnauthorized, errors.New("Invalid Token"))
				varianceControl <- false
				return
			}

			for i, fn := range accessCheckFunctions {
				if fn(tokenContainer, ctx) {
					varianceControl <- true
					break
				}

				if len(accessCheckFunctions)-1 == i {
					ctx.AbortWithError(http.StatusForbidden, errors.New("Access to the Resource is forbidden"))
					varianceControl <- false
					return
				}
			}
		}()

		select {
		case ok := <-varianceControl:
			if !ok {
				glog.V(2).Infof("[Gin-OAuth] %12v %s access not allowed", time.Since(t), ctx.Request.URL.Path)
				return
			}
		case <-time.After(VarianceTimer):
			ctx.AbortWithError(http.StatusGatewayTimeout, errors.New("Authorization check overtime"))
			glog.V(2).Infof("[Gin-OAuth] %12v %s overtime", time.Since(t), ctx.Request.URL.Path)
			return
		}

		glog.V(2).Infof("[Gin-OAuth] %12v %s access allowed", time.Since(t), ctx.Request.URL.Path)
	}
}

func RequestLogger(keys []string, contentKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		request := c.Request
		c.Next()
		err := c.Errors
		if request.Method != "GET" && err == nil {
			data, e := c.Get(contentKey)
			if e != false { //key is non existent
				values := make([]string, 0)
				for _, key := range keys {
					val, keyPresent := c.Get(key)
					if keyPresent {
						values = append(values, val.(string))
					}
				}
				glog.Infof("[Gin-OAuth] Request: %+v for %s", data, strings.Join(values, "-"))
			}
		}
	}
}

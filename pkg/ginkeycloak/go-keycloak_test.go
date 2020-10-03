package ginkeycloak

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

const dummyPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAySQYhjHeQ3STWV8wJjXPJ7bBkvzQwxHbvBm5cOyvIAQ5xAmE
+700/Lfhgz97cag7eRKEfWHWQ09Ju9SBZoMt1imOIPO0F6xQT1cixiNxXWkkbRd4
g4HBqzAMQVhuBS28bRhfuqXSUiPXCuXSDJNAwzada5oG0jgJ79gn+D8oH2Uh/uQd
nGUvOHk96/15BJcxMpx8fV4/k066xkg5AeikangFOc024hHSJn+SDxjdkb7Nf/tH
WCZrYMWGjbEzzoTJasnZl3HkMH4OW66RA4G4TgcQCPfT9yoXK7uGjv4Hhiq1JP/A
Xj8xyt+xlJSPr7C2Q/WBJVvpjxAFFDccsKnikwIDAQABAoIBAQCj6/jYlJeQ3dag
BUVWPpAey4AibEsuTsWHHGfWse1e6FKzgxaPmnkuZCUzM29FB1fAqeizziIyJNHw
c5UpmEqouKEOFc51ZIbmwhqi44umFuQKzA/5DKxq+PNj5c90BPwE5NJPaIhpTLAa
P4XZncAv17ifUp2wgN8ISl74n2/xdKTPN/4Ico0rdTs7oZYXU//bwivQbaaHVQ1H
EDng/hTWMwKbGEYElQYPbyV03ogzi4a0pFs3XLuybMXHQDOajGZ3Dbw5QJFTzMvd
6tZobkvH4hKZxTWEHS/PMhaQFxpvTsj3B5OzeEsKhfW65ok0q/4zldqM5wXfir+q
PDx0KSyxAoGBAPg4S2OFmVbhvr06EWke+n4+Kco9x3o5MnIVZAuIAGe7SomFl5c4
8IrwQ1J1S5k6E+MSwVNIFUbChMbxOI0FuAjWX4lIob9EB3dIUPc6vY+Vf9PT7Fgf
eDOtsez9y+t67MBy77utKrgupgakWnwoJnYAUY56vWRUv0XI2JQ3/gW3AoGBAM9y
CtNgGWspSbU7okJV0YD7qpOPXjea/fW2TOImxB3zE91vWPGNODIcQq+k+rqxjKG0
bX/IhAJ3bS38oXmhMvmQF0gFSHBdj5VAN1cuxRQNVCNojXKTcAgcH9TbafJe4rGX
yL3EkZxxUndP/e6Ms4Ztg0SRSO5RndV2bljYWmoFAoGAFFPP4LOVLidIjoiN2nT+
AI6or3ZFur2qYutbiRI3LkeJQB/fnTO9hzNL4BnY+hBmhocHrAFQNL5DT2N7xRi9
zIN5yW1YSaiRj/QtJUH7OiH9GOTXCxRwrJLB6m2SYJNthgkjltQElpbDY/HbsyU6
mRlHlIp6rhe+nkFncyPuupsCgYAY3EPr3QJu0z3gGEtzw7Ed0gs5L99Mrqhsv/Iq
0BaEuFLTILr6B8CKUNS1FAJwSULfRi4xOCiJ2yIcdsArQWRIgDoqCWgK/0tryYxY
SGSZ6JcCv07kQkMU1boC2mCyCSkFu3j1NQ92PiZx4gY+hmIlZA5tMzQYS3Os10qW
HyeGuQKBgDwxkTONg1s76VWvVwOYusg7Gq5HL+TomovEJncAHPEt1UaCEaL6FUs2
qw8cwOOnFqaARMKBYY3khxhhTufZkLM3rDYqTYvE6QiWq6Cm+9abJoSkx3QegCew
71cpTprRof2GcDiriSPaRlJtT7Q283rOsZsPBW+PYTgulWrmEfJ8
-----END RSA PRIVATE KEY-----`

const dummyPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAySQYhjHeQ3STWV8wJjXP
J7bBkvzQwxHbvBm5cOyvIAQ5xAmE+700/Lfhgz97cag7eRKEfWHWQ09Ju9SBZoMt
1imOIPO0F6xQT1cixiNxXWkkbRd4g4HBqzAMQVhuBS28bRhfuqXSUiPXCuXSDJNA
wzada5oG0jgJ79gn+D8oH2Uh/uQdnGUvOHk96/15BJcxMpx8fV4/k066xkg5Aeik
angFOc024hHSJn+SDxjdkb7Nf/tHWCZrYMWGjbEzzoTJasnZl3HkMH4OW66RA4G4
TgcQCPfT9yoXK7uGjv4Hhiq1JP/AXj8xyt+xlJSPr7C2Q/WBJVvpjxAFFDccsKni
kwIDAQAB
-----END PUBLIC KEY-----`

var signedToken string
var serviceName = "myService"
var username = "u123456"

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	var err error
	pubBlock, _ := pem.Decode([]byte(dummyPublicKey))
	pubKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	privBlock, _ := pem.Decode([]byte(dummyPrivateKey))
	privKey, _ := x509.ParsePKCS1PrivateKey(privBlock.Bytes)

	expiredDate := time.Now().Add(time.Minute * 1)
	token := KeyCloakToken{}
	token.Exp = expiredDate.Unix()
	token.ResourceAccess = make(map[string]ServiceRole)
	token.ResourceAccess[serviceName] = ServiceRole{[]string{"test"}}
	token.PreferredUsername = username
	token.RealmAccess.Roles = []string{"a_realm_role", "another_realm_role"}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		log.Fatal(err)
	}

	signedToken, err = jwt.Signed(sig).Claims(&token).CompactSerialize()
	if err != nil {
		panic(err)
	}

	raw, _ := jwt.ParseSigned(signedToken)
	publicKey := pubKey.(*rsa.PublicKey)
	be := big.NewInt(int64(publicKey.E))
	ke := KeyEntry{
		Kid: "",
		Kty: "RSA",
		Alg: "RS256",
		Use: "sig",
		N:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(be.Bytes()),
	}
	_ = publicKeyCache.Add(raw.Headers[0].KeyID, Certs{Keys: []KeyEntry{ke}}, time.Minute)
	os.Exit(m.Run())
}

func Test_RoleAccess_not_right_role(t *testing.T) {
	roles := []AccessTuple{{Service: serviceName, Role: "anotherrole"}}
	authfunc := Auth(GroupCheck(roles), KeycloakConfig{})
	ctx := buildContext()

	authfunc(ctx)

	assert.True(t, len(ctx.Errors) == 1)
	assert.Equal(t, "Access to the Resource is forbidden", ctx.Errors[0].Err.Error())
}

func Test_RealmAccess_not_right_role(t *testing.T) {
	allowedRoles := []string{"anotherrole"}
	authfunc := Auth(RealmCheck(allowedRoles), KeycloakConfig{})
	ctx := buildContext()

	authfunc(ctx)

	assert.True(t, len(ctx.Errors) == 1)
	assert.Equal(t, "Access to the Resource is forbidden", ctx.Errors[0].Err.Error())
}

func Test_RoleAccess_right_role(t *testing.T) {
	roles := []AccessTuple{{Service: serviceName, Role: "test"}}
	authfunc := Auth(GroupCheck(roles), KeycloakConfig{})
	ctx := buildContext()

	authfunc(ctx)

	assert.True(t, len(ctx.Errors) == 0)
}

func Test_RealmAccess_right_role(t *testing.T) {
	roles := []string{"a_realm_role"}
	authfunc := Auth(RealmCheck(roles), KeycloakConfig{})
	ctx := buildContext()

	authfunc(ctx)

	assert.True(t, len(ctx.Errors) == 0)
}

func Test_RoleAccess_right_uid(t *testing.T) {
	uids := []AccessTuple{{Service: serviceName, Uid: username}}
	authfunc := Auth(UidCheck(uids), KeycloakConfig{})
	ctx := buildContext()

	authfunc(ctx)

	assert.True(t, len(ctx.Errors) == 0)
}

func Test_RoleAccess_not_right_ud(t *testing.T) {
	uids := []AccessTuple{{Service: serviceName, Uid: "another"}}
	authfunc := Auth(UidCheck(uids), KeycloakConfig{})
	ctx := buildContext()

	authfunc(ctx)

	assert.True(t, len(ctx.Errors) == 1)
	assert.Equal(t, "Access to the Resource is forbidden", ctx.Errors[0].Err.Error())
}

func Test_RoleAccess_auth_check(t *testing.T) {
	authfunc := Auth(AuthCheck(), KeycloakConfig{})
	ctx := buildContext()

	authfunc(ctx)

	assert.True(t, len(ctx.Errors) == 0)
}

func buildContext() *gin.Context {
	resp := httptest.NewRecorder()
	ctx, r := gin.CreateTestContext(resp)
	r.GET("", func(c *gin.Context) {
		c.Status(200)
	})
	ctx.Request, _ = http.NewRequest(http.MethodGet, "/test", nil)
	ctx.Request.Header.Set("Authorization", "Bearer "+signedToken)
	return ctx
}

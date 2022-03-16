package ginkeycloak

import (
	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
)

type BuilderConfig struct {
	Service              string
	Url                  string
	Realm                string
	FullCertsPath        *string
	DisableSecurityCheck bool
}

type RestrictedAccessBuilder interface {
	RestrictButForRole(role string) RestrictedAccessBuilder
	RestrictButForUid(uid string) RestrictedAccessBuilder
	RestrictButForRealm(realmName string) RestrictedAccessBuilder
	Build() gin.HandlerFunc
}

type restrictedAccessBuilderImpl struct {
	allowedRoles  []AccessTuple
	allowedUids   []AccessTuple
	allowedRealms []string
	config        BuilderConfig
}

func NewAccessBuilder(config BuilderConfig) RestrictedAccessBuilder {
	builder := restrictedAccessBuilderImpl{config: config, allowedRoles: []AccessTuple{}}
	return builder
}

func (builder restrictedAccessBuilderImpl) RestrictButForRole(role string) RestrictedAccessBuilder {
	builder.allowedRoles = append(builder.allowedRoles, AccessTuple{Service: builder.config.Service, Role: string(role)})
	return builder
}

func (builder restrictedAccessBuilderImpl) RestrictButForUid(uid string) RestrictedAccessBuilder {
	builder.allowedUids = append(builder.allowedUids, AccessTuple{Service: builder.config.Service, Uid: uid})
	return builder
}

func (builder restrictedAccessBuilderImpl) RestrictButForRealm(realmName string) RestrictedAccessBuilder {
	builder.allowedRealms = append(builder.allowedRealms, realmName)
	return builder
}

func (builder restrictedAccessBuilderImpl) Build() gin.HandlerFunc {
	if builder.config.DisableSecurityCheck {
		glog.Warningf("[ginkeycloak] access check is disabled")
		return func(ctx *gin.Context) {}
	}
	return Auth(builder.checkIfOneConditionMatches(), builder.keycloakConfig())
}

func (builder restrictedAccessBuilderImpl) keycloakConfig() KeycloakConfig {
	return KeycloakConfig{
		Url:           builder.config.Url,
		Realm:         builder.config.Realm,
		FullCertsPath: builder.config.FullCertsPath,
	}
}

func (builder restrictedAccessBuilderImpl) checkIfOneConditionMatches() AccessCheckFunction {
	return func(tc *TokenContainer, ctx *gin.Context) bool {
		checkRoles := GroupCheck(builder.allowedRoles)(tc, ctx)
		checkUids := UidCheck(builder.allowedUids)(tc, ctx)
		checkRealm := RealmCheck(builder.allowedRealms)(tc, ctx)

		return checkRoles || checkUids || checkRealm
	}
}

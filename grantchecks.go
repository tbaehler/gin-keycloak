// Package zalando contains Zalando specific definitions for
// authorization.
package ginkeycloak

import (
	"github.com/gin-gonic/gin"
)

// AccessTuple is the type defined for use in AccessTuples.
type AccessTuple struct {
	Service string
	Role    string
	Uid     string
}

func GroupCheck(at []AccessTuple) func(tc *TokenContainer, ctx *gin.Context) bool {
	ats := at
	return func(tc *TokenContainer, ctx *gin.Context) bool {
		ctx.Set("token", *tc.KeyCloakToken)
		ctx.Set("uid", tc.KeyCloakToken.PreferredUsername)
		for idx := range ats {
			at := ats[idx]
			if tc.KeyCloakToken.ResourceAccess != nil {
				serviceRoles := tc.KeyCloakToken.ResourceAccess[at.Service]
				for _, role := range serviceRoles.Roles {
					if (role == at.Role) {
						return true;
					}
				}
			}
		}
		return false
	}
}

func UidCheck(at []AccessTuple) func(tc *TokenContainer, ctx *gin.Context) bool {
	ats := at
	return func(tc *TokenContainer, ctx *gin.Context) bool {
		ctx.Set("token", *tc.KeyCloakToken)
		ctx.Set("uid", tc.KeyCloakToken.PreferredUsername)
		uid := tc.KeyCloakToken.PreferredUsername
		for idx := range ats {
			at := ats[idx]
			if at.Uid == uid {
				return true
			}
		}
		return false
	}
}

package ginkeycloak

import "github.com/gin-gonic/gin"

type ErrorResponse struct {
	Msg string `json:"message"`
}

func NewErrorResponse(ctx *gin.Context, msg error) ErrorResponse {
	_ = ctx.Error(msg)
	return ErrorResponse{
		Msg: msg.Error(),
	}
}

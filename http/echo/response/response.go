package response

import (
	"github.com/cgholdings/go-common/http/model"
	"github.com/cgholdings/go-common/http/model/error_code"
	"github.com/labstack/echo/v4"
)

func Response(c echo.Context, resp interface{}, err error) error {
	if err == nil {
		r := model.CreateResponse("0", "Success", resp)
		return c.JSON(200, r)
	}

	switch respError := resp.(type) {
	case model.Error:
		r := model.CreateResponse(respError.Code, "Failed", respError.Data)
		return c.JSON(400, r)
	case *model.Error:
		r := model.CreateResponse(respError.Code, "Failed", respError.Data)
		return c.JSON(400, r)
	default:
		errCode := err.Error()
		r := model.CreateResponse(error_code.GetErrorCode(errCode), error_code.GetErrorMessage(errCode), nil)
		return c.JSON(error_code.GetHTTPStatusCode(errCode), r)
	}
}

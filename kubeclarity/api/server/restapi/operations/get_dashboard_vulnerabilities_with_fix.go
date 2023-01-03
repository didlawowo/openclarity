// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// GetDashboardVulnerabilitiesWithFixHandlerFunc turns a function with the right signature into a get dashboard vulnerabilities with fix handler
type GetDashboardVulnerabilitiesWithFixHandlerFunc func(GetDashboardVulnerabilitiesWithFixParams) middleware.Responder

// Handle executing the request and returning a response
func (fn GetDashboardVulnerabilitiesWithFixHandlerFunc) Handle(params GetDashboardVulnerabilitiesWithFixParams) middleware.Responder {
	return fn(params)
}

// GetDashboardVulnerabilitiesWithFixHandler interface for that can handle valid get dashboard vulnerabilities with fix params
type GetDashboardVulnerabilitiesWithFixHandler interface {
	Handle(GetDashboardVulnerabilitiesWithFixParams) middleware.Responder
}

// NewGetDashboardVulnerabilitiesWithFix creates a new http.Handler for the get dashboard vulnerabilities with fix operation
func NewGetDashboardVulnerabilitiesWithFix(ctx *middleware.Context, handler GetDashboardVulnerabilitiesWithFixHandler) *GetDashboardVulnerabilitiesWithFix {
	return &GetDashboardVulnerabilitiesWithFix{Context: ctx, Handler: handler}
}

/* GetDashboardVulnerabilitiesWithFix swagger:route GET /dashboard/vulnerabilitiesWithFix getDashboardVulnerabilitiesWithFix

Get vulnerabilities with fix available per severity

*/
type GetDashboardVulnerabilitiesWithFix struct {
	Context *middleware.Context
	Handler GetDashboardVulnerabilitiesWithFixHandler
}

func (o *GetDashboardVulnerabilitiesWithFix) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewGetDashboardVulnerabilitiesWithFixParams()
	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request
	o.Context.Respond(rw, r, route.Produces, route, res)

}
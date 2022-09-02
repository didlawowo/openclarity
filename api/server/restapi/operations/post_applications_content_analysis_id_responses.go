// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openclarity/kubeclarity/api/server/models"
)

// PostApplicationsContentAnalysisIDCreatedCode is the HTTP code returned for type PostApplicationsContentAnalysisIDCreated
const PostApplicationsContentAnalysisIDCreatedCode int = 201

/*PostApplicationsContentAnalysisIDCreated Application content analysis successfully reported.

swagger:response postApplicationsContentAnalysisIdCreated
*/
type PostApplicationsContentAnalysisIDCreated struct {
}

// NewPostApplicationsContentAnalysisIDCreated creates PostApplicationsContentAnalysisIDCreated with default headers values
func NewPostApplicationsContentAnalysisIDCreated() *PostApplicationsContentAnalysisIDCreated {

	return &PostApplicationsContentAnalysisIDCreated{}
}

// WriteResponse to the client
func (o *PostApplicationsContentAnalysisIDCreated) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(201)
}

// PostApplicationsContentAnalysisIDNotFoundCode is the HTTP code returned for type PostApplicationsContentAnalysisIDNotFound
const PostApplicationsContentAnalysisIDNotFoundCode int = 404

/*PostApplicationsContentAnalysisIDNotFound Application not found.

swagger:response postApplicationsContentAnalysisIdNotFound
*/
type PostApplicationsContentAnalysisIDNotFound struct {
}

// NewPostApplicationsContentAnalysisIDNotFound creates PostApplicationsContentAnalysisIDNotFound with default headers values
func NewPostApplicationsContentAnalysisIDNotFound() *PostApplicationsContentAnalysisIDNotFound {

	return &PostApplicationsContentAnalysisIDNotFound{}
}

// WriteResponse to the client
func (o *PostApplicationsContentAnalysisIDNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(404)
}

/*PostApplicationsContentAnalysisIDDefault unknown error

swagger:response postApplicationsContentAnalysisIdDefault
*/
type PostApplicationsContentAnalysisIDDefault struct {
	_statusCode int

	/*
	  In: Body
	*/
	Payload *models.APIResponse `json:"body,omitempty"`
}

// NewPostApplicationsContentAnalysisIDDefault creates PostApplicationsContentAnalysisIDDefault with default headers values
func NewPostApplicationsContentAnalysisIDDefault(code int) *PostApplicationsContentAnalysisIDDefault {
	if code <= 0 {
		code = 500
	}

	return &PostApplicationsContentAnalysisIDDefault{
		_statusCode: code,
	}
}

// WithStatusCode adds the status to the post applications content analysis ID default response
func (o *PostApplicationsContentAnalysisIDDefault) WithStatusCode(code int) *PostApplicationsContentAnalysisIDDefault {
	o._statusCode = code
	return o
}

// SetStatusCode sets the status to the post applications content analysis ID default response
func (o *PostApplicationsContentAnalysisIDDefault) SetStatusCode(code int) {
	o._statusCode = code
}

// WithPayload adds the payload to the post applications content analysis ID default response
func (o *PostApplicationsContentAnalysisIDDefault) WithPayload(payload *models.APIResponse) *PostApplicationsContentAnalysisIDDefault {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the post applications content analysis ID default response
func (o *PostApplicationsContentAnalysisIDDefault) SetPayload(payload *models.APIResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PostApplicationsContentAnalysisIDDefault) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(o._statusCode)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
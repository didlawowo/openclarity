// Code generated by go-swagger; DO NOT EDIT.

package project

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/openclarity/kubeclarity/shared/pkg/scanner/dependency_track/api/client/models"
)

// GetProject1Reader is a Reader for the GetProject1 structure.
type GetProject1Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetProject1Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetProject1OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetProject1Unauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetProject1Forbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetProject1NotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetProject1OK creates a GetProject1OK with default headers values
func NewGetProject1OK() *GetProject1OK {
	return &GetProject1OK{}
}

/* GetProject1OK describes a response with status code 200, with default header values.

successful operation
*/
type GetProject1OK struct {
	Payload *models.Project
}

func (o *GetProject1OK) Error() string {
	return fmt.Sprintf("[GET /v1/project/lookup][%d] getProject1OK  %+v", 200, o.Payload)
}
func (o *GetProject1OK) GetPayload() *models.Project {
	return o.Payload
}

func (o *GetProject1OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Project)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetProject1Unauthorized creates a GetProject1Unauthorized with default headers values
func NewGetProject1Unauthorized() *GetProject1Unauthorized {
	return &GetProject1Unauthorized{}
}

/* GetProject1Unauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetProject1Unauthorized struct {
}

func (o *GetProject1Unauthorized) Error() string {
	return fmt.Sprintf("[GET /v1/project/lookup][%d] getProject1Unauthorized ", 401)
}

func (o *GetProject1Unauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetProject1Forbidden creates a GetProject1Forbidden with default headers values
func NewGetProject1Forbidden() *GetProject1Forbidden {
	return &GetProject1Forbidden{}
}

/* GetProject1Forbidden describes a response with status code 403, with default header values.

Access to the specified project is forbidden
*/
type GetProject1Forbidden struct {
}

func (o *GetProject1Forbidden) Error() string {
	return fmt.Sprintf("[GET /v1/project/lookup][%d] getProject1Forbidden ", 403)
}

func (o *GetProject1Forbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewGetProject1NotFound creates a GetProject1NotFound with default headers values
func NewGetProject1NotFound() *GetProject1NotFound {
	return &GetProject1NotFound{}
}

/* GetProject1NotFound describes a response with status code 404, with default header values.

The project could not be found
*/
type GetProject1NotFound struct {
}

func (o *GetProject1NotFound) Error() string {
	return fmt.Sprintf("[GET /v1/project/lookup][%d] getProject1NotFound ", 404)
}

func (o *GetProject1NotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

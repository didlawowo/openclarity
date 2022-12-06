// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DashboardCounters dashboard counters
//
// swagger:model DashboardCounters
type DashboardCounters struct {

	// applications
	Applications uint32 `json:"applications,omitempty"`

	// packages
	Packages uint32 `json:"packages,omitempty"`

	// resources
	Resources uint32 `json:"resources,omitempty"`
}

// Validate validates this dashboard counters
func (m *DashboardCounters) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this dashboard counters based on context it is used
func (m *DashboardCounters) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DashboardCounters) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DashboardCounters) UnmarshalBinary(b []byte) error {
	var res DashboardCounters
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
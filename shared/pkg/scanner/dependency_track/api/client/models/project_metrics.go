// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// ProjectMetrics project metrics
//
// swagger:model ProjectMetrics
type ProjectMetrics struct {

	// components
	Components int32 `json:"components,omitempty"`

	// critical
	Critical int32 `json:"critical,omitempty"`

	// findings audited
	FindingsAudited int32 `json:"findingsAudited,omitempty"`

	// findings total
	FindingsTotal int32 `json:"findingsTotal,omitempty"`

	// findings unaudited
	FindingsUnaudited int32 `json:"findingsUnaudited,omitempty"`

	// first occurrence
	// Required: true
	// Format: date-time
	FirstOccurrence *strfmt.DateTime `json:"firstOccurrence"`

	// high
	High int32 `json:"high,omitempty"`

	// inherited risk score
	InheritedRiskScore float64 `json:"inheritedRiskScore,omitempty"`

	// last occurrence
	// Required: true
	// Format: date-time
	LastOccurrence *strfmt.DateTime `json:"lastOccurrence"`

	// low
	Low int32 `json:"low,omitempty"`

	// medium
	Medium int32 `json:"medium,omitempty"`

	// policy violations audited
	PolicyViolationsAudited int32 `json:"policyViolationsAudited,omitempty"`

	// policy violations fail
	PolicyViolationsFail int32 `json:"policyViolationsFail,omitempty"`

	// policy violations info
	PolicyViolationsInfo int32 `json:"policyViolationsInfo,omitempty"`

	// policy violations license audited
	PolicyViolationsLicenseAudited int32 `json:"policyViolationsLicenseAudited,omitempty"`

	// policy violations license total
	PolicyViolationsLicenseTotal int32 `json:"policyViolationsLicenseTotal,omitempty"`

	// policy violations license unaudited
	PolicyViolationsLicenseUnaudited int32 `json:"policyViolationsLicenseUnaudited,omitempty"`

	// policy violations operational audited
	PolicyViolationsOperationalAudited int32 `json:"policyViolationsOperationalAudited,omitempty"`

	// policy violations operational total
	PolicyViolationsOperationalTotal int32 `json:"policyViolationsOperationalTotal,omitempty"`

	// policy violations operational unaudited
	PolicyViolationsOperationalUnaudited int32 `json:"policyViolationsOperationalUnaudited,omitempty"`

	// policy violations security audited
	PolicyViolationsSecurityAudited int32 `json:"policyViolationsSecurityAudited,omitempty"`

	// policy violations security total
	PolicyViolationsSecurityTotal int32 `json:"policyViolationsSecurityTotal,omitempty"`

	// policy violations security unaudited
	PolicyViolationsSecurityUnaudited int32 `json:"policyViolationsSecurityUnaudited,omitempty"`

	// policy violations total
	PolicyViolationsTotal int32 `json:"policyViolationsTotal,omitempty"`

	// policy violations unaudited
	PolicyViolationsUnaudited int32 `json:"policyViolationsUnaudited,omitempty"`

	// policy violations warn
	PolicyViolationsWarn int32 `json:"policyViolationsWarn,omitempty"`

	// project
	// Required: true
	Project *Project `json:"project"`

	// suppressed
	Suppressed int32 `json:"suppressed,omitempty"`

	// unassigned
	Unassigned int32 `json:"unassigned,omitempty"`

	// vulnerabilities
	Vulnerabilities int64 `json:"vulnerabilities,omitempty"`

	// vulnerable components
	VulnerableComponents int32 `json:"vulnerableComponents,omitempty"`
}

// Validate validates this project metrics
func (m *ProjectMetrics) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateFirstOccurrence(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastOccurrence(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProject(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ProjectMetrics) validateFirstOccurrence(formats strfmt.Registry) error {

	if err := validate.Required("firstOccurrence", "body", m.FirstOccurrence); err != nil {
		return err
	}

	if err := validate.FormatOf("firstOccurrence", "body", "date-time", m.FirstOccurrence.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *ProjectMetrics) validateLastOccurrence(formats strfmt.Registry) error {

	if err := validate.Required("lastOccurrence", "body", m.LastOccurrence); err != nil {
		return err
	}

	if err := validate.FormatOf("lastOccurrence", "body", "date-time", m.LastOccurrence.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *ProjectMetrics) validateProject(formats strfmt.Registry) error {

	if err := validate.Required("project", "body", m.Project); err != nil {
		return err
	}

	if m.Project != nil {
		if err := m.Project.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("project")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this project metrics based on the context it is used
func (m *ProjectMetrics) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateProject(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ProjectMetrics) contextValidateProject(ctx context.Context, formats strfmt.Registry) error {

	if m.Project != nil {
		if err := m.Project.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("project")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *ProjectMetrics) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ProjectMetrics) UnmarshalBinary(b []byte) error {
	var res ProjectMetrics
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
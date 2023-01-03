// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// ExternalReference external reference
//
// swagger:model ExternalReference
type ExternalReference struct {

	// comment
	Comment string `json:"comment,omitempty"`

	// type
	// Enum: [vcs issue-tracker website advisories bom mailing-list social chat documentation support distribution license build-meta build-system other]
	Type string `json:"type,omitempty"`

	// url
	URL string `json:"url,omitempty"`
}

// Validate validates this external reference
func (m *ExternalReference) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var externalReferenceTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["vcs","issue-tracker","website","advisories","bom","mailing-list","social","chat","documentation","support","distribution","license","build-meta","build-system","other"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		externalReferenceTypeTypePropEnum = append(externalReferenceTypeTypePropEnum, v)
	}
}

const (

	// ExternalReferenceTypeVcs captures enum value "vcs"
	ExternalReferenceTypeVcs string = "vcs"

	// ExternalReferenceTypeIssueDashTracker captures enum value "issue-tracker"
	ExternalReferenceTypeIssueDashTracker string = "issue-tracker"

	// ExternalReferenceTypeWebsite captures enum value "website"
	ExternalReferenceTypeWebsite string = "website"

	// ExternalReferenceTypeAdvisories captures enum value "advisories"
	ExternalReferenceTypeAdvisories string = "advisories"

	// ExternalReferenceTypeBom captures enum value "bom"
	ExternalReferenceTypeBom string = "bom"

	// ExternalReferenceTypeMailingDashList captures enum value "mailing-list"
	ExternalReferenceTypeMailingDashList string = "mailing-list"

	// ExternalReferenceTypeSocial captures enum value "social"
	ExternalReferenceTypeSocial string = "social"

	// ExternalReferenceTypeChat captures enum value "chat"
	ExternalReferenceTypeChat string = "chat"

	// ExternalReferenceTypeDocumentation captures enum value "documentation"
	ExternalReferenceTypeDocumentation string = "documentation"

	// ExternalReferenceTypeSupport captures enum value "support"
	ExternalReferenceTypeSupport string = "support"

	// ExternalReferenceTypeDistribution captures enum value "distribution"
	ExternalReferenceTypeDistribution string = "distribution"

	// ExternalReferenceTypeLicense captures enum value "license"
	ExternalReferenceTypeLicense string = "license"

	// ExternalReferenceTypeBuildDashMeta captures enum value "build-meta"
	ExternalReferenceTypeBuildDashMeta string = "build-meta"

	// ExternalReferenceTypeBuildDashSystem captures enum value "build-system"
	ExternalReferenceTypeBuildDashSystem string = "build-system"

	// ExternalReferenceTypeOther captures enum value "other"
	ExternalReferenceTypeOther string = "other"
)

// prop value enum
func (m *ExternalReference) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, externalReferenceTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *ExternalReference) validateType(formats strfmt.Registry) error {
	if swag.IsZero(m.Type) { // not required
		return nil
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", m.Type); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this external reference based on context it is used
func (m *ExternalReference) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ExternalReference) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ExternalReference) UnmarshalBinary(b []byte) error {
	var res ExternalReference
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
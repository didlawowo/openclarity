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

// ProjectProperty project property
//
// swagger:model ProjectProperty
type ProjectProperty struct {

	// description
	// Max Length: 255
	// Min Length: 0
	Description *string `json:"description,omitempty"`

	// group name
	// Max Length: 255
	// Min Length: 1
	GroupName string `json:"groupName,omitempty"`

	// project
	Project *Project `json:"project,omitempty"`

	// property name
	// Max Length: 255
	// Min Length: 1
	PropertyName string `json:"propertyName,omitempty"`

	// property type
	// Required: true
	// Enum: [BOOLEAN INTEGER NUMBER STRING ENCRYPTEDSTRING TIMESTAMP URL UUID]
	PropertyType *string `json:"propertyType"`

	// property value
	// Max Length: 1024
	// Min Length: 0
	PropertyValue *string `json:"propertyValue,omitempty"`
}

// Validate validates this project property
func (m *ProjectProperty) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDescription(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateGroupName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProject(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePropertyName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePropertyType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePropertyValue(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ProjectProperty) validateDescription(formats strfmt.Registry) error {
	if swag.IsZero(m.Description) { // not required
		return nil
	}

	if err := validate.MinLength("description", "body", *m.Description, 0); err != nil {
		return err
	}

	if err := validate.MaxLength("description", "body", *m.Description, 255); err != nil {
		return err
	}

	return nil
}

func (m *ProjectProperty) validateGroupName(formats strfmt.Registry) error {
	if swag.IsZero(m.GroupName) { // not required
		return nil
	}

	if err := validate.MinLength("groupName", "body", m.GroupName, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("groupName", "body", m.GroupName, 255); err != nil {
		return err
	}

	return nil
}

func (m *ProjectProperty) validateProject(formats strfmt.Registry) error {
	if swag.IsZero(m.Project) { // not required
		return nil
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

func (m *ProjectProperty) validatePropertyName(formats strfmt.Registry) error {
	if swag.IsZero(m.PropertyName) { // not required
		return nil
	}

	if err := validate.MinLength("propertyName", "body", m.PropertyName, 1); err != nil {
		return err
	}

	if err := validate.MaxLength("propertyName", "body", m.PropertyName, 255); err != nil {
		return err
	}

	return nil
}

var projectPropertyTypePropertyTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["BOOLEAN","INTEGER","NUMBER","STRING","ENCRYPTEDSTRING","TIMESTAMP","URL","UUID"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		projectPropertyTypePropertyTypePropEnum = append(projectPropertyTypePropertyTypePropEnum, v)
	}
}

const (

	// ProjectPropertyPropertyTypeBOOLEAN captures enum value "BOOLEAN"
	ProjectPropertyPropertyTypeBOOLEAN string = "BOOLEAN"

	// ProjectPropertyPropertyTypeINTEGER captures enum value "INTEGER"
	ProjectPropertyPropertyTypeINTEGER string = "INTEGER"

	// ProjectPropertyPropertyTypeNUMBER captures enum value "NUMBER"
	ProjectPropertyPropertyTypeNUMBER string = "NUMBER"

	// ProjectPropertyPropertyTypeSTRING captures enum value "STRING"
	ProjectPropertyPropertyTypeSTRING string = "STRING"

	// ProjectPropertyPropertyTypeENCRYPTEDSTRING captures enum value "ENCRYPTEDSTRING"
	ProjectPropertyPropertyTypeENCRYPTEDSTRING string = "ENCRYPTEDSTRING"

	// ProjectPropertyPropertyTypeTIMESTAMP captures enum value "TIMESTAMP"
	ProjectPropertyPropertyTypeTIMESTAMP string = "TIMESTAMP"

	// ProjectPropertyPropertyTypeURL captures enum value "URL"
	ProjectPropertyPropertyTypeURL string = "URL"

	// ProjectPropertyPropertyTypeUUID captures enum value "UUID"
	ProjectPropertyPropertyTypeUUID string = "UUID"
)

// prop value enum
func (m *ProjectProperty) validatePropertyTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, projectPropertyTypePropertyTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *ProjectProperty) validatePropertyType(formats strfmt.Registry) error {

	if err := validate.Required("propertyType", "body", m.PropertyType); err != nil {
		return err
	}

	// value enum
	if err := m.validatePropertyTypeEnum("propertyType", "body", *m.PropertyType); err != nil {
		return err
	}

	return nil
}

func (m *ProjectProperty) validatePropertyValue(formats strfmt.Registry) error {
	if swag.IsZero(m.PropertyValue) { // not required
		return nil
	}

	if err := validate.MinLength("propertyValue", "body", *m.PropertyValue, 0); err != nil {
		return err
	}

	if err := validate.MaxLength("propertyValue", "body", *m.PropertyValue, 1024); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this project property based on the context it is used
func (m *ProjectProperty) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateProject(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ProjectProperty) contextValidateProject(ctx context.Context, formats strfmt.Registry) error {

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
func (m *ProjectProperty) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ProjectProperty) UnmarshalBinary(b []byte) error {
	var res ProjectProperty
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// Copyright © 2023 Cisco Systems, Inc. and its affiliates.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package assetscanwatcher

import (
	"fmt"
	"strings"
)

type DeleteJobPolicyType string

const (
	DeleteJobPolicyAlways    DeleteJobPolicyType = "Always"
	DeleteJobPolicyNever     DeleteJobPolicyType = "Never"
	DeleteJobPolicyOnSuccess DeleteJobPolicyType = "OnSuccess"
)

func (p *DeleteJobPolicyType) UnmarshalText(text []byte) error {
	var policy DeleteJobPolicyType

	switch strings.ToLower(string(text)) {
	case strings.ToLower(string(DeleteJobPolicyAlways)):
		policy = DeleteJobPolicyAlways
	case strings.ToLower(string(DeleteJobPolicyNever)):
		policy = DeleteJobPolicyNever
	case strings.ToLower(string(DeleteJobPolicyOnSuccess)):
		policy = DeleteJobPolicyOnSuccess
	default:
		return fmt.Errorf("failed to unmarshal text into Delete Policy: %s", text)
	}

	*p = policy

	return nil
}

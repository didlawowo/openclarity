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

package azure

import (
	apitypes "github.com/openclarity/vmclarity/api/types"
)

const (
	ProvisioningStateSucceeded = "Succeeded"
)

type ScanScope struct {
	AllResourceGroups bool
	ResourceGroups    []ResourceGroup
	ScanStopped       bool
	// Only assets that have these tags will be selected for scanning within the selected scan scope.
	// Multiple tags will be treated as an AND operator.
	TagSelector []apitypes.Tag
	// Assets that have these tags will be excluded from the scan, even if they match the tag selector.
	// Multiple tags will be treated as an AND operator.
	ExcludeTags []apitypes.Tag
}

type ResourceGroup struct {
	Name string
}

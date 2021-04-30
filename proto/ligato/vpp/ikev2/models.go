//  Copyright (c) 2020 Doc.ai and/or its affiliates.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package vpp_ikev2

import (
	"go.ligato.io/vpp-agent/v3/pkg/models"
)

// ModuleName is the module name used for models.
const ModuleName = "vpp.ikev2"

var (
	ModelIkev2Profile = models.Register(&Ikev2Profile{}, models.Spec{
		Module:  ModuleName,
		Version: "v1",
		Type:    "profile",
	}, models.WithNameTemplate("{{.Name}}"))

	ModelIkev2Liveness = models.Register(&Ikev2Liveness{}, models.Spec{
		Module:  ModuleName,
		Version: "v1",
		Type:    "liveness",
	})
)

// Copyright 2020 The gVisor Authors.
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

package injector

import (
	"fmt"
	"io/ioutil"
)

var (
	caKey      []byte
	caCert     []byte
	serverKey  []byte
	serverCert []byte
)

func certLoad(certPath string) []byte {
	bytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		panic(err)
	}
	return bytes
}

func init() {
	var certErr error
	defer func() {
		if r := recover(); r != nil {
			certErr = r.(error)
		}
	}()
	caKey = certLoad("caKey.pem")
	caCert = certLoad("caCert.pem")
	serverKey = certLoad("serverKey.pem")
	serverCert = certLoad("serverCert.pem")
	if certErr != nil {
		panic(fmt.Errorf("unable to create certificates: %v", certErr))
	}
}

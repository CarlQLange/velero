/*
Copyright The Velero Contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1api "k8s.io/api/core/v1"
)

func TestRestoreSpecEncryptionPrivateKeyRef(t *testing.T) {
	tests := []struct {
		name    string
		restore *Restore
	}{
		{
			name: "RestoreSpec accepts EncryptionPrivateKeyRef",
			restore: &Restore{
				Spec: RestoreSpec{
					BackupName: "my-backup",
					EncryptionPrivateKeyRef: &corev1api.SecretKeySelector{
						LocalObjectReference: corev1api.LocalObjectReference{
							Name: "velero-restore-enc-key",
						},
						Key: "key",
					},
				},
			},
		},
		{
			name: "RestoreSpec without EncryptionPrivateKeyRef",
			restore: &Restore{
				Spec: RestoreSpec{
					BackupName: "my-backup",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// This test primarily verifies that the EncryptionPrivateKeyRef
			// field exists and is usable on RestoreSpec.
			assert.Equal(t, "my-backup", test.restore.Spec.BackupName)
		})
	}
}

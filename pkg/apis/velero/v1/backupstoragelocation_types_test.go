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

	corev1api "k8s.io/api/core/v1"
)

func TestBackupStorageLocationValidate(t *testing.T) {
	tests := []struct {
		name        string
		bsl         *BackupStorageLocation
		expectError bool
	}{
		{
			name: "valid - neither CACert nor CACertRef set",
			bsl: &BackupStorageLocation{
				Spec: BackupStorageLocationSpec{
					StorageType: StorageType{
						ObjectStorage: &ObjectStorageLocation{
							Bucket: "test-bucket",
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid - only CACert set",
			bsl: &BackupStorageLocation{
				Spec: BackupStorageLocationSpec{
					StorageType: StorageType{
						ObjectStorage: &ObjectStorageLocation{
							Bucket: "test-bucket",
							CACert: []byte("test-cert"),
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid - only CACertRef set",
			bsl: &BackupStorageLocation{
				Spec: BackupStorageLocationSpec{
					StorageType: StorageType{
						ObjectStorage: &ObjectStorageLocation{
							Bucket: "test-bucket",
							CACertRef: &corev1api.SecretKeySelector{
								LocalObjectReference: corev1api.LocalObjectReference{
									Name: "ca-cert-secret",
								},
								Key: "ca.crt",
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid - both CACert and CACertRef set",
			bsl: &BackupStorageLocation{
				Spec: BackupStorageLocationSpec{
					StorageType: StorageType{
						ObjectStorage: &ObjectStorageLocation{
							Bucket: "test-bucket",
							CACert: []byte("test-cert"),
							CACertRef: &corev1api.SecretKeySelector{
								LocalObjectReference: corev1api.LocalObjectReference{
									Name: "ca-cert-secret",
								},
								Key: "ca.crt",
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "valid - no ObjectStorage",
			bsl: &BackupStorageLocation{
				Spec: BackupStorageLocationSpec{
					StorageType: StorageType{
						ObjectStorage: nil,
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid - only EncryptionPublicKeyRef set (encrypt-only mode)",
			bsl: &BackupStorageLocation{
				Spec: BackupStorageLocationSpec{
					StorageType: StorageType{
						ObjectStorage: &ObjectStorageLocation{
							Bucket: "test-bucket",
							EncryptionPublicKeyRef: &corev1api.SecretKeySelector{
								LocalObjectReference: corev1api.LocalObjectReference{
									Name: "velero-encryption-public",
								},
								Key: "key",
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid - both encryption refs set (convenience mode)",
			bsl: &BackupStorageLocation{
				Spec: BackupStorageLocationSpec{
					StorageType: StorageType{
						ObjectStorage: &ObjectStorageLocation{
							Bucket: "test-bucket",
							EncryptionPublicKeyRef: &corev1api.SecretKeySelector{
								LocalObjectReference: corev1api.LocalObjectReference{
									Name: "velero-encryption-public",
								},
								Key: "key",
							},
							EncryptionPrivateKeyRef: &corev1api.SecretKeySelector{
								LocalObjectReference: corev1api.LocalObjectReference{
									Name: "velero-encryption-private",
								},
								Key: "key",
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid - EncryptionPrivateKeyRef without EncryptionPublicKeyRef",
			bsl: &BackupStorageLocation{
				Spec: BackupStorageLocationSpec{
					StorageType: StorageType{
						ObjectStorage: &ObjectStorageLocation{
							Bucket: "test-bucket",
							EncryptionPrivateKeyRef: &corev1api.SecretKeySelector{
								LocalObjectReference: corev1api.LocalObjectReference{
									Name: "velero-encryption-private",
								},
								Key: "key",
							},
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "valid - encryption refs with CACertRef (orthogonal features)",
			bsl: &BackupStorageLocation{
				Spec: BackupStorageLocationSpec{
					StorageType: StorageType{
						ObjectStorage: &ObjectStorageLocation{
							Bucket: "test-bucket",
							CACertRef: &corev1api.SecretKeySelector{
								LocalObjectReference: corev1api.LocalObjectReference{
									Name: "ca-cert-secret",
								},
								Key: "ca.crt",
							},
							EncryptionPublicKeyRef: &corev1api.SecretKeySelector{
								LocalObjectReference: corev1api.LocalObjectReference{
									Name: "velero-encryption-public",
								},
								Key: "key",
							},
							EncryptionPrivateKeyRef: &corev1api.SecretKeySelector{
								LocalObjectReference: corev1api.LocalObjectReference{
									Name: "velero-encryption-private",
								},
								Key: "key",
							},
						},
					},
				},
			},
			expectError: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.bsl.Validate()
			if test.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !test.expectError && err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
		})
	}
}

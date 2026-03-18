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

package persistence

import (
	"bytes"
	"io"

	"filippo.io/age"
	"github.com/pkg/errors"
)

// encryptionMagic is the prefix of any age-encrypted object, used to detect
// whether an object is encrypted for backward-compatible passthrough.
const encryptionMagic = "age-encryption.org/v1"

// newEncryptingReader returns a reader that produces age-encrypted output.
// The plaintext is encrypted to all provided recipients.
func newEncryptingReader(recipients []age.Recipient, plaintext io.Reader) (io.Reader, error) {
	if len(recipients) == 0 {
		return nil, errors.New("at least one encryption recipient is required")
	}

	pr, pw := io.Pipe()
	go func() {
		w, err := age.Encrypt(pw, recipients...)
		if err != nil {
			pw.CloseWithError(errors.Wrap(err, "error initializing age encryption"))
			return
		}
		if _, err := io.Copy(w, plaintext); err != nil {
			pw.CloseWithError(errors.Wrap(err, "error encrypting data"))
			return
		}
		if err := w.Close(); err != nil {
			pw.CloseWithError(errors.Wrap(err, "error finalizing age encryption"))
			return
		}
		pw.Close()
	}()

	return pr, nil
}

// newDecryptingReader returns a reader that decrypts age-encrypted data.
// If the data does not start with the age header, it is returned unchanged
// (backward compatibility with unencrypted backups).
func newDecryptingReader(identities []age.Identity, src io.Reader) (io.Reader, error) {
	// Read enough bytes to check for the age header.
	header := make([]byte, len(encryptionMagic))
	n, err := io.ReadFull(src, header)

	if err != nil || string(header[:n]) != encryptionMagic {
		// Not age-encrypted — return the original data unchanged.
		return io.MultiReader(bytes.NewReader(header[:n]), src), nil
	}

	// It's encrypted. Check that we have identities to decrypt with.
	if len(identities) == 0 {
		return nil, errors.New("encrypted backup detected but no decryption key (encryptionPrivateKeyRef) is configured")
	}

	// Reconstruct the full stream (header + remainder) and decrypt.
	fullSrc := io.MultiReader(bytes.NewReader(header[:n]), src)
	r, err := age.Decrypt(fullSrc, identities...)
	if err != nil {
		return nil, errors.Wrap(err, "error decrypting age-encrypted data")
	}

	return r, nil
}

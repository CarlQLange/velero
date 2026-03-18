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
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	return id
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	id := testIdentity(t)

	plaintext := []byte("hello, velero client-side encryption!")

	er, err := newEncryptingReader([]age.Recipient{id.Recipient()}, bytes.NewReader(plaintext))
	require.NoError(t, err)

	ciphertext, err := io.ReadAll(er)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext, "ciphertext should differ from plaintext")

	dr, err := newDecryptingReader([]age.Identity{id}, bytes.NewReader(ciphertext))
	require.NoError(t, err)

	got, err := io.ReadAll(dr)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestEncryptDecryptLargeData(t *testing.T) {
	id := testIdentity(t)

	// 3 MiB — exercises streaming across multiple internal chunks.
	plaintext := make([]byte, 3<<20)
	for i := range plaintext {
		plaintext[i] = byte(i % 251)
	}

	er, err := newEncryptingReader([]age.Recipient{id.Recipient()}, bytes.NewReader(plaintext))
	require.NoError(t, err)

	ciphertext, err := io.ReadAll(er)
	require.NoError(t, err)

	dr, err := newDecryptingReader([]age.Identity{id}, bytes.NewReader(ciphertext))
	require.NoError(t, err)

	got, err := io.ReadAll(dr)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestEncryptDecryptEmptyData(t *testing.T) {
	id := testIdentity(t)

	er, err := newEncryptingReader([]age.Recipient{id.Recipient()}, bytes.NewReader([]byte{}))
	require.NoError(t, err)

	ciphertext, err := io.ReadAll(er)
	require.NoError(t, err)

	dr, err := newDecryptingReader([]age.Identity{id}, bytes.NewReader(ciphertext))
	require.NoError(t, err)

	got, err := io.ReadAll(dr)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestDecryptUnencryptedPassthrough(t *testing.T) {
	id := testIdentity(t)

	// Data without the age header should pass through unchanged.
	plaintext := []byte("this is a legacy unencrypted backup object")

	r, err := newDecryptingReader([]age.Identity{id}, bytes.NewReader(plaintext))
	require.NoError(t, err)

	got, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestDecryptShortUnencryptedPassthrough(t *testing.T) {
	id := testIdentity(t)

	// Fewer bytes than the age header — can't be encrypted, should pass through.
	plaintext := []byte("hi")

	r, err := newDecryptingReader([]age.Identity{id}, bytes.NewReader(plaintext))
	require.NoError(t, err)

	got, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestDecryptTamperedDataFails(t *testing.T) {
	id := testIdentity(t)
	plaintext := []byte("sensitive backup data with secrets inside")

	er, err := newEncryptingReader([]age.Recipient{id.Recipient()}, bytes.NewReader(plaintext))
	require.NoError(t, err)

	ciphertext, err := io.ReadAll(er)
	require.NoError(t, err)

	// Flip the last byte of the payload.
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0xFF

	dr, err := newDecryptingReader([]age.Identity{id}, bytes.NewReader(tampered))
	// age may return error at Decrypt or at Read — either is acceptable.
	if err != nil {
		return
	}
	_, err = io.ReadAll(dr)
	assert.Error(t, err, "tampered ciphertext should fail authentication")
}

func TestDecryptWrongKeyFails(t *testing.T) {
	id1 := testIdentity(t)
	id2 := testIdentity(t)

	er, err := newEncryptingReader([]age.Recipient{id1.Recipient()}, bytes.NewReader([]byte("my backup data")))
	require.NoError(t, err)

	ciphertext, err := io.ReadAll(er)
	require.NoError(t, err)

	dr, err := newDecryptingReader([]age.Identity{id2}, bytes.NewReader(ciphertext))
	// age may return error at Decrypt or at Read.
	if err != nil {
		return
	}
	_, err = io.ReadAll(dr)
	assert.Error(t, err, "wrong private key should fail decryption")
}

func TestDecryptWithoutIdentitiesFails(t *testing.T) {
	id := testIdentity(t)

	er, err := newEncryptingReader([]age.Recipient{id.Recipient()}, bytes.NewReader([]byte("encrypted data")))
	require.NoError(t, err)

	ciphertext, err := io.ReadAll(er)
	require.NoError(t, err)

	// No identities — should fail with a clear error about missing private key.
	_, err = newDecryptingReader(nil, bytes.NewReader(ciphertext))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no decryption key")
}

func TestEncryptedDataStartsWithAgeHeader(t *testing.T) {
	id := testIdentity(t)

	er, err := newEncryptingReader([]age.Recipient{id.Recipient()}, bytes.NewReader([]byte("anything")))
	require.NoError(t, err)

	ciphertext, err := io.ReadAll(er)
	require.NoError(t, err)

	require.Greater(t, len(ciphertext), len(encryptionMagic))
	assert.Equal(t, encryptionMagic, string(ciphertext[:len(encryptionMagic)]))
}

func TestMultipleRecipients(t *testing.T) {
	id1 := testIdentity(t)
	id2 := testIdentity(t)

	plaintext := []byte("backup encrypted to two recipients")

	// Encrypt to both recipients.
	er, err := newEncryptingReader(
		[]age.Recipient{id1.Recipient(), id2.Recipient()},
		bytes.NewReader(plaintext),
	)
	require.NoError(t, err)

	ciphertext, err := io.ReadAll(er)
	require.NoError(t, err)

	// Either identity should be able to decrypt independently.
	for _, id := range []*age.X25519Identity{id1, id2} {
		dr, err := newDecryptingReader([]age.Identity{id}, bytes.NewReader(ciphertext))
		require.NoError(t, err)

		got, err := io.ReadAll(dr)
		require.NoError(t, err)
		assert.Equal(t, plaintext, got)
	}
}

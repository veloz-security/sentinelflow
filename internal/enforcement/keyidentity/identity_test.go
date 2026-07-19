package keyidentity

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"regexp"
	"testing"
)

func TestDeriveIsStableAndRoleSeparated(t *testing.T) {
	dispatch := publicFromByte(0x11)
	result := publicFromByte(0x22)

	first, err := Derive(dispatch, result)
	if err != nil {
		t.Fatalf("derive identities: %v", err)
	}
	second, err := Derive(bytes.Clone(dispatch), bytes.Clone(result))
	if err != nil {
		t.Fatalf("derive cloned identities: %v", err)
	}
	if first != second {
		t.Fatalf("identity derivation is not stable: %#v != %#v", first, second)
	}
	if first.DispatchKeyID == first.ResultKeyID || first.ResultKeyID == first.ExecutorID || first.DispatchKeyID == first.ExecutorID {
		t.Fatalf("role-separated identities collided: %#v", first)
	}

	valid := regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	for name, value := range map[string]string{
		"dispatch": first.DispatchKeyID,
		"result":   first.ResultKeyID,
		"executor": first.ExecutorID,
	} {
		if !valid.MatchString(value) {
			t.Fatalf("%s identity is not contract compatible: %q", name, value)
		}
	}
}

func TestDeriveChangesWithEitherKey(t *testing.T) {
	baseline, _ := Derive(publicFromByte(0x11), publicFromByte(0x22))
	dispatchChanged, _ := Derive(publicFromByte(0x12), publicFromByte(0x22))
	resultChanged, _ := Derive(publicFromByte(0x11), publicFromByte(0x23))

	if baseline.DispatchKeyID == dispatchChanged.DispatchKeyID {
		t.Fatal("dispatch identity did not change with dispatch key")
	}
	if baseline.ResultKeyID != dispatchChanged.ResultKeyID || baseline.ExecutorID != dispatchChanged.ExecutorID {
		t.Fatal("dispatch key unexpectedly changed result identities")
	}
	if baseline.ResultKeyID == resultChanged.ResultKeyID || baseline.ExecutorID == resultChanged.ExecutorID {
		t.Fatal("result identities did not change with result key")
	}
	if baseline.DispatchKeyID != resultChanged.DispatchKeyID {
		t.Fatal("result key unexpectedly changed dispatch identity")
	}
}

func TestDeriveRejectsInvalidKeys(t *testing.T) {
	valid := publicFromByte(0x11)
	for name, test := range map[string]struct {
		dispatch ed25519.PublicKey
		result   ed25519.PublicKey
	}{
		"nil dispatch":   {nil, valid},
		"short dispatch": {make(ed25519.PublicKey, ed25519.PublicKeySize-1), valid},
		"zero dispatch":  {make(ed25519.PublicKey, ed25519.PublicKeySize), valid},
		"nil result":     {valid, nil},
		"short result":   {valid, make(ed25519.PublicKey, ed25519.PublicKeySize-1)},
		"zero result":    {valid, make(ed25519.PublicKey, ed25519.PublicKeySize)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Derive(test.dispatch, test.result); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("got %v, want ErrInvalidKey", err)
			}
		})
	}
}

func publicFromByte(value byte) ed25519.PublicKey {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{value}, ed25519.SeedSize))
	return private.Public().(ed25519.PublicKey)
}

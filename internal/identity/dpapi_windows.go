//go:build windows

package identity

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows DPAPI binding.
//
// This calls the operating system's CryptProtectData / CryptUnprotectData. It
// implements no cryptography: Windows chooses and applies the cipher, keyed by
// material derived from the user's logon credentials and held by the OS.
//
// What this buys: the sealed blob is bound to this Windows user on this machine.
// Copying identity.json to another computer, or reading it from a different
// account, or recovering it from a backup or a pulled disk, yields nothing.
//
// What this does not buy: any process running AS this user can call
// CryptUnprotectData with the same entropy and get the seed back. DPAPI is a
// defence against offline access to the file, not against local malware.

var (
	crypt32              = windows.NewLazySystemDLL("crypt32.dll")
	procCryptProtectData = crypt32.NewProc("CryptProtectData")
	procCryptUnprotect   = crypt32.NewProc("CryptUnprotectData")
)

// dpapiEntropy is the application-specific secondary entropy.
//
// Without it, any other program running as the same user could unseal this blob
// by accident simply by passing it to CryptUnprotectData. With it, a caller has
// to know this constant, which at least means the unsealing is deliberate.
var dpapiEntropy = []byte("CMD-Chat identity v2 DPAPI entropy")

// CRYPTPROTECT_UI_FORBIDDEN: never show a UI. A terminal application that
// blocked on a hidden dialog would look like a hang.
const cryptProtectUIForbidden = 0x1

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(b []byte) dataBlob {
	if len(b) == 0 {
		return dataBlob{}
	}
	return dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}

// bytes copies the blob out of OS-owned memory before it is freed.
func (b dataBlob) bytes() []byte {
	if b.pbData == nil || b.cbData == 0 {
		return nil
	}
	out := make([]byte, b.cbData)
	copy(out, unsafe.Slice(b.pbData, b.cbData))
	return out
}

func (b dataBlob) free() {
	if b.pbData != nil {
		_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(b.pbData)))
	}
}

func dpapiAvailable() bool {
	return crypt32.Load() == nil &&
		procCryptProtectData.Find() == nil &&
		procCryptUnprotect.Find() == nil
}

func dpapiProtect(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("identity: nothing to protect")
	}
	in := newBlob(plaintext)
	entropy := newBlob(dpapiEntropy)
	var out dataBlob

	ret, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, // szDataDescr
		uintptr(unsafe.Pointer(&entropy)),
		0, // pvReserved
		0, // pPromptStruct
		cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&out)),
	)
	if ret == 0 {
		return nil, err
	}
	defer out.free()
	return out.bytes(), nil
}

func dpapiUnprotect(sealed []byte) ([]byte, error) {
	if len(sealed) == 0 {
		return nil, errors.New("identity: nothing to unprotect")
	}
	in := newBlob(sealed)
	entropy := newBlob(dpapiEntropy)
	var out dataBlob

	ret, _, err := procCryptUnprotect.Call(
		uintptr(unsafe.Pointer(&in)),
		0, // ppszDataDescr
		uintptr(unsafe.Pointer(&entropy)),
		0, // pvReserved
		0, // pPromptStruct
		cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&out)),
	)
	if ret == 0 {
		return nil, errors.New("identity: this identity file was sealed for a different Windows account or machine: " + err.Error())
	}
	defer out.free()
	return out.bytes(), nil
}

//go:build linux

package tpm

import (
	"github.com/google/go-tpm/tpm2"

	"github.com/atas/nazar/core/platform"
)

// srkTemplate is the storage root key every nazar key is a child of: the
// TCG reference ECC P-256 storage primary in the owner hierarchy. A primary
// is derived from the TPM's seed and its template, so the same template
// gives the same key after a restart, and the children wrapped to it load
// again. No authorization value: the owner hierarchy's is empty on a
// desktop, and the children's protection is the vault folder's mode plus
// nazar's gates (spec, "Weaker than macOS" 2), not a TPM password.
var srkTemplate = tpm2.ECCSRKTemplate

// keyAttributes are every nazar key's: made inside this TPM (fixedTPM,
// sensitiveDataOrigin), never re-parented or duplicated (fixedParent),
// usable with its empty auth value (userWithAuth) and never locking the
// TPM out after failures (noDA). Sign or decrypt is added per purpose.
var keyAttributes = tpm2.TPMAObject{
	FixedTPM:            true,
	FixedParent:         true,
	SensitiveDataOrigin: true,
	UserWithAuth:        true,
	NoDA:                true,
}

// keyTemplate is the public template of a key for purpose: ECC NIST P-256,
// signing with ECDSA-SHA256 for PurposeSign, ECDH for PurposeKeyAgreement.
// ok is false for any other purpose. Symmetric and KDF are left at their
// zero values, which marshal as TPM_ALG_NULL: what an unrestricted key
// must say.
func keyTemplate(purpose platform.Purpose) (t tpm2.TPMTPublic, ok bool) {
	attrs := keyAttributes
	var scheme tpm2.TPMTECCScheme
	switch purpose {
	case platform.PurposeSign:
		attrs.SignEncrypt = true
		scheme = tpm2.TPMTECCScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
		}
	case platform.PurposeKeyAgreement:
		attrs.Decrypt = true
		scheme = tpm2.TPMTECCScheme{
			Scheme:  tpm2.TPMAlgECDH,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDH, &tpm2.TPMSKeySchemeECDH{HashAlg: tpm2.TPMAlgSHA256}),
		}
	default:
		return tpm2.TPMTPublic{}, false
	}
	return tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgECC,
		NameAlg:          tpm2.TPMAlgSHA256,
		ObjectAttributes: attrs,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme:  scheme,
			CurveID: tpm2.TPMECCNistP256,
		}),
	}, true
}

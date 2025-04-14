#include <psa/crypto.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <kernel/panic.h>
#include <stdlib.h>
#include <string.h>

#if defined(MBEDTLS_PSA_CRYPTO_C)
struct psa_ecc_keypair {
	psa_key_id_t key_id;
};

struct psa_ecc_public_key {
	psa_key_id_t key_id;
};

/*
 * Convert TEE curve to PSA curve family (currently assumes NIST P-curves).
 * You can expand this if using Brainpool or others.
 */
static psa_ecc_family_t tee_curve_to_psa(uint32_t curve)
{
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192: return PSA_ECC_FAMILY_SECP_R1;
	case TEE_ECC_CURVE_NIST_P224: return PSA_ECC_FAMILY_SECP_R1;
	case TEE_ECC_CURVE_NIST_P256: return PSA_ECC_FAMILY_SECP_R1;
	case TEE_ECC_CURVE_NIST_P384: return PSA_ECC_FAMILY_SECP_R1;
	case TEE_ECC_CURVE_NIST_P521: return PSA_ECC_FAMILY_SECP_R1;
	default:
		panic("Unsupported curve");
	}
}

// TEE_Result crypto_acipher_alloc_ecc_keypair(struct ecc_keypair *s,
// 					     uint32_t curve, size_t key_size)
// {
// 	struct psa_ecc_keypair *key = (struct psa_ecc_keypair *)s;
// 	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
// 	psa_status_t status;

// 	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(tee_curve_to_psa(curve)));
// 	psa_set_key_bits(&attr, key_size);
// 	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
// 	psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

// 	status = psa_generate_key(&attr, &key->key_id);
// 	return (status == PSA_SUCCESS) ? TEE_SUCCESS : TEE_ERROR_GENERIC;
// }

// void crypto_acipher_free_ecc_keypair(struct ecc_keypair *s)
// {
// 	struct psa_ecc_keypair *key = (struct psa_ecc_keypair *)s;
// 	if (key && key->key_id)
// 		psa_destroy_key(key->key_id);
// }

// TEE_Result crypto_acipher_alloc_ecc_public_key(struct ecc_public_key *s,
// 					       uint32_t curve, size_t key_size __unused)
// {
// 	struct psa_ecc_public_key *key = (struct psa_ecc_public_key *)s;
// 	(void)curve;
// 	key->key_id = 0;
// 	return TEE_SUCCESS;
// }

// void crypto_acipher_free_ecc_public_key(struct ecc_public_key *s)
// {
// 	struct psa_ecc_public_key *key = (struct psa_ecc_public_key *)s;
// 	if (key && key->key_id)
// 		psa_destroy_key(key->key_id);
// }

// TEE_Result crypto_acipher_ecc_sign(uint32_t algo __unused, struct ecc_keypair *s,
// 				    const uint8_t *msg, size_t msg_len,
// 				    uint8_t *sig, size_t *sig_len)
// {
// 	struct psa_ecc_keypair *key = (struct psa_ecc_keypair *)s;
// 	psa_status_t status;

// 	status = psa_sign_hash(key->key_id,
// 			       PSA_ALG_ECDSA(PSA_ALG_SHA_256),
// 			       msg, msg_len, sig, *sig_len, sig_len);

// 	return (status == PSA_SUCCESS) ? TEE_SUCCESS : TEE_ERROR_GENERIC;
// }

// TEE_Result crypto_acipher_ecc_verify(uint32_t algo __unused, struct ecc_public_key *s,
// 				     const uint8_t *msg, size_t msg_len,
// 				     const uint8_t *sig, size_t sig_len)
// {
// 	struct psa_ecc_public_key *key = (struct psa_ecc_public_key *)s;
// 	psa_status_t status;

// 	status = psa_verify_hash(key->key_id,
// 				 PSA_ALG_ECDSA(PSA_ALG_SHA_256),
// 				 msg, msg_len, sig, sig_len);

// 	return (status == PSA_SUCCESS) ? TEE_SUCCESS : TEE_ERROR_SIGNATURE_INVALID;
// }


TEE_Result crypto_asym_alloc_ecc_public_key(struct ecc_public_key *s,
	uint32_t curve, size_t key_size __unused)
{
struct psa_ecc_public_key *key = (struct psa_ecc_public_key *)s;
(void)curve;
key->key_id = 0;
return TEE_SUCCESS;
}

TEE_Result crypto_asym_alloc_ecc_keypair(struct ecc_keypair *s,
  uint32_t curve, size_t key_size)
{
struct psa_ecc_keypair *key = (struct psa_ecc_keypair *)s;
psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
psa_status_t status;

psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(tee_curve_to_psa(curve)));
psa_set_key_bits(&attr, key_size);
psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

status = psa_generate_key(&attr, &key->key_id);
return (status == PSA_SUCCESS) ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}


#endif

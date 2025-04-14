#include <psa/crypto.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <stdlib.h>
#include <string.h>
#include <kernel/panic.h>
#if defined(MBEDTLS_PSA_CRYPTO_C)
struct psa_dh_keypair {
	psa_key_id_t key_id;
};

/*
 * Allocates a DH keypair using PSA and stores the key ID in the OP-TEE struct.
 */
TEE_Result crypto_acipher_alloc_dh_keypair(struct dh_keypair *key, size_t key_size)
{
	struct psa_dh_keypair *psa = calloc(1, sizeof(*psa));
	if (!psa)
		return TEE_ERROR_OUT_OF_MEMORY;

	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status;

	psa_set_key_type(&attr, PSA_KEY_TYPE_DH_KEY_PAIR(PSA_DH_FAMILY_RFC7919));
	psa_set_key_bits(&attr, key_size);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_FFDH);

	status = psa_generate_key(&attr, &psa->key_id);
	if (status != PSA_SUCCESS) {
		free(psa);
		return TEE_ERROR_GENERIC;
	}

	memcpy(key, psa, sizeof(*psa));
	free(psa);
	return TEE_SUCCESS;
}

/*
 * Generates DH keypair (NOP since PSA already handles it in alloc).
 */
TEE_Result crypto_acipher_gen_dh_key(struct dh_keypair *key,
				     struct bignum *q __unused,
				     size_t xbits __unused,
				     size_t key_size __unused)
{
	(void)key;
	return TEE_SUCCESS;
}

/*
 * Frees the PSA key associated with this DH keypair.
 */
void crypto_acipher_free_dh_keypair(struct dh_keypair *key)
{
	struct psa_dh_keypair *psa = (struct psa_dh_keypair *)key;
	if (psa->key_id)
		psa_destroy_key(psa->key_id);
	memset(key, 0, sizeof(*key));
}

/*
 * Performs DH key agreement using PSA raw key agreement.
 */
TEE_Result crypto_acipher_dh_shared_secret(struct dh_keypair *private_key,
					   struct bignum *peer_pub,
					   struct bignum *secret)
{
	struct psa_dh_keypair *psa = (struct psa_dh_keypair *)private_key;
	uint8_t peer_pub_buf[512] = {0};
	uint8_t secret_buf[512] = {0};
	size_t pub_len = crypto_bignum_num_bytes(peer_pub);
	size_t sec_len = sizeof(secret_buf);
	psa_status_t status;

	if (pub_len > sizeof(peer_pub_buf))
		return TEE_ERROR_SHORT_BUFFER;

	crypto_bignum_bn2bin(peer_pub, peer_pub_buf);

	status = psa_raw_key_agreement(PSA_ALG_FFDH,
				       psa->key_id,
				       peer_pub_buf, pub_len,
				       secret_buf, sizeof(secret_buf),
				       &sec_len);

	if (status != PSA_SUCCESS)
		return TEE_ERROR_GENERIC;

	return crypto_bignum_bin2bn(secret_buf, sec_len, secret);
}
#endif
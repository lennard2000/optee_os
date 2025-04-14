#if defined(MBEDTLS_PSA_CRYPTO_C)

#include <psa/crypto.h>
#include <crypto/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <kernel/panic.h>
#include <trace.h>

struct psa_rsa_public_key {
	psa_key_id_t key_id;
};

struct psa_rsa_keypair {
	psa_key_id_t key_id;
};

TEE_Result crypto_acipher_alloc_rsa_public_key(struct rsa_public_key *key,
					       size_t key_size __unused)
{
	struct psa_rsa_public_key *psa_key = (struct psa_rsa_public_key *)key;
	psa_key->key_id = 0;
	return TEE_SUCCESS;
}

TEE_Result crypto_acipher_alloc_rsa_keypair(struct rsa_keypair *key,
					    size_t key_size __unused)
{
	struct psa_rsa_keypair *psa_key = (struct psa_rsa_keypair *)key;
	psa_key->key_id = 0;
	return TEE_SUCCESS;
}

void crypto_acipher_free_rsa_public_key(struct rsa_public_key *key)
{
	struct psa_rsa_public_key *psa_key = (struct psa_rsa_public_key *)key;

	if (psa_key && psa_key->key_id != 0)
		psa_destroy_key(psa_key->key_id);
}

TEE_Result crypto_acipher_rsassa_verify(uint32_t algo,
					struct rsa_public_key *key,
					int salt_len __unused,
					const uint8_t *msg, size_t msg_len,
					const uint8_t *sig, size_t sig_len)
{
	struct psa_rsa_public_key *k = (struct psa_rsa_public_key *)key;
	psa_status_t status = psa_verify_message(
		k->key_id,
		algo,
		msg, msg_len,
		sig, sig_len);

	return (status == PSA_SUCCESS) ? TEE_SUCCESS : TEE_ERROR_SIGNATURE_INVALID;
}

TEE_Result crypto_acipher_rsassa_sign(uint32_t algo,
				      struct rsa_keypair *key,
				      int salt_len __unused,
				      const uint8_t *msg, size_t msg_len,
				      uint8_t *sig, size_t *sig_len)
{
	struct psa_rsa_keypair *k = (struct psa_rsa_keypair *)key;
	psa_status_t status = psa_sign_message(
		k->key_id,
		algo,
		msg, msg_len,
		sig, sig_len, &sig_len);

	return (status == PSA_SUCCESS) ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

TEE_Result crypto_acipher_rsanopad_encrypt(struct rsa_public_key *key,
					   const uint8_t *msg, size_t msg_len,
					   uint8_t *enc_msg, size_t *enc_msg_len)
{
	struct psa_rsa_public_key *k = (struct psa_rsa_public_key *)key;
	psa_status_t status = psa_asymmetric_encrypt(
		k->key_id,
		PSA_ALG_RSA_PKCS1V15_CRYPT,
		msg, msg_len,
		NULL, 0,
		enc_msg, *enc_msg_len, enc_msg_len);

	return (status == PSA_SUCCESS) ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

TEE_Result crypto_acipher_rsanopad_decrypt(struct rsa_keypair *key,
					   const uint8_t *enc_msg, size_t enc_msg_len,
					   uint8_t *msg, size_t *msg_len)
{
	struct psa_rsa_keypair *k = (struct psa_rsa_keypair *)key;
	psa_status_t status = psa_asymmetric_decrypt(
		k->key_id,
		PSA_ALG_RSA_PKCS1V15_CRYPT,
		enc_msg, enc_msg_len,
		NULL, 0,
		msg, *msg_len, msg_len);

	return (status == PSA_SUCCESS) ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

TEE_Result crypto_acipher_rsaes_encrypt(uint32_t algo,
					struct rsa_public_key *key,
					const uint8_t *msg, size_t msg_len,
					uint32_t label __unused,
					const uint8_t *label_buf __unused, size_t label_len __unused,
					uint8_t *enc_msg, size_t *enc_msg_len)
{
	(void)algo;
	return crypto_acipher_rsanopad_encrypt(key, msg, msg_len, enc_msg, enc_msg_len);
}

TEE_Result crypto_acipher_rsaes_decrypt(uint32_t algo,
					struct rsa_keypair *key,
					const uint8_t *enc_msg, size_t enc_msg_len,
					uint32_t label __unused,
					const uint8_t *label_buf __unused, size_t label_len __unused,
					uint8_t *msg, size_t *msg_len)
{
	(void)algo;
	return crypto_acipher_rsanopad_decrypt(key, enc_msg, enc_msg_len, msg, msg_len);
}

TEE_Result crypto_acipher_gen_rsa_key(struct rsa_keypair *key, size_t key_size)
{
	struct psa_rsa_keypair *k = (struct psa_rsa_keypair *)key;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status;

	psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
	psa_set_key_bits(&attr, key_size);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&attr, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));

	status = psa_generate_key(&attr, &k->key_id);

	return (status == PSA_SUCCESS) ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

#endif /* MBEDTLS_PSA_CRYPTO_C */

// SPDX-License-Identifier: BSD-2-Clause
#include <psa/crypto.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <stdlib.h>
#include <string.h>
#include <kernel/panic.h>

#if defined(MBEDTLS_PSA_CRYPTO_C)

struct psa_mac_ctx {
	struct crypto_mac_ctx ctx;
	psa_mac_operation_t op;
	mbedtls_svc_key_id_t key;
	psa_algorithm_t alg;
};

static TEE_Result mac_init(struct crypto_mac_ctx *ctx, TEE_OperationMode mode,
			   const uint8_t *key, size_t key_len, const uint8_t *nonce __unused,
			   size_t nonce_len __unused, uint32_t algo)
{
	struct psa_mac_ctx *mac_ctx = (struct psa_mac_ctx *)ctx;
	psa_status_t status;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

	psa_set_key_usage_flags(&attr,
		mode == TEE_MODE_MAC ? PSA_KEY_USAGE_SIGN_HASH : PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&attr, algo);
	psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
	psa_set_key_bits(&attr, key_len * 8);
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);

	status = psa_import_key(&attr, key, key_len, &mac_ctx->key);
	if (status != PSA_SUCCESS)
		return TEE_ERROR_GENERIC;

	mac_ctx->alg = algo;

	if (mode == TEE_MODE_MAC)
		status = psa_mac_sign_setup(&mac_ctx->op, mac_ctx->key, algo);
	else
		status = psa_mac_verify_setup(&mac_ctx->op, mac_ctx->key, algo);

	if (status != PSA_SUCCESS)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result mac_update(struct crypto_mac_ctx *ctx, const uint8_t *data, size_t len)
{
	struct psa_mac_ctx *mac_ctx = (struct psa_mac_ctx *)ctx;
	psa_status_t status = psa_mac_update(&mac_ctx->op, data, len);
	return (status == PSA_SUCCESS) ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

static TEE_Result mac_final(struct crypto_mac_ctx *ctx, uint8_t *digest, size_t len)
{
	struct psa_mac_ctx *mac_ctx = (struct psa_mac_ctx *)ctx;
	size_t out_len = 0;

	psa_status_t status = psa_mac_sign_finish(&mac_ctx->op, digest, len, &out_len);
	psa_destroy_key(mac_ctx->key);

	return (status == PSA_SUCCESS) ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

static void mac_free_ctx(struct crypto_mac_ctx *ctx)
{
	struct psa_mac_ctx *mac_ctx = (struct psa_mac_ctx *)ctx;

	psa_mac_abort(&mac_ctx->op);
	if (mac_ctx->key)
		psa_destroy_key(mac_ctx->key);

	free(mac_ctx);
}

static void mac_copy_state(struct crypto_mac_ctx *dst __unused,
			   struct crypto_mac_ctx *src __unused)
{
	panic("copy_state not supported");
}

static const struct crypto_mac_ops psa_mac_ops = {
	.init = mac_init,
	.update = mac_update,
	.final = mac_final,
	.free_ctx = mac_free_ctx,
	.copy_state = mac_copy_state,
};

/* --- Factory functions --- */

#define HMAC_ALLOC_FN(NAME, ALG_CONST) \
TEE_Result crypto_hmac_##NAME##_alloc_ctx(struct crypto_mac_ctx **ctx) \
{ \
	struct psa_mac_ctx *mac_ctx = calloc(1, sizeof(*mac_ctx)); \
	if (!mac_ctx) \
		return TEE_ERROR_OUT_OF_MEMORY; \
	mac_ctx->ctx.ops = &psa_mac_ops; \
	mac_ctx->alg = PSA_ALG_HMAC(ALG_CONST); \
	*ctx = &mac_ctx->ctx; \
	return TEE_SUCCESS; \
}

HMAC_ALLOC_FN(md5, PSA_ALG_MD5)
HMAC_ALLOC_FN(sha1, PSA_ALG_SHA_1)
HMAC_ALLOC_FN(sha224, PSA_ALG_SHA_224)
HMAC_ALLOC_FN(sha256, PSA_ALG_SHA_256)
HMAC_ALLOC_FN(sha384, PSA_ALG_SHA_384)
HMAC_ALLOC_FN(sha512, PSA_ALG_SHA_512)

#define CMAC_ALLOC_FN(NAME, KEY_TYPE) \
TEE_Result crypto_##NAME##_cmac_alloc_ctx(struct crypto_mac_ctx **ctx) \
{ \
	struct psa_mac_ctx *mac_ctx = calloc(1, sizeof(*mac_ctx)); \
	if (!mac_ctx) \
		return TEE_ERROR_OUT_OF_MEMORY; \
	mac_ctx->ctx.ops = &psa_mac_ops; \
	mac_ctx->alg = PSA_ALG_CMAC; \
	*ctx = &mac_ctx->ctx; \
	return TEE_SUCCESS; \
}

CMAC_ALLOC_FN(aes, PSA_KEY_TYPE_AES)
CMAC_ALLOC_FN(des3, PSA_KEY_TYPE_DES)

#endif // MBEDTLS_PSA_CRYPTO_C

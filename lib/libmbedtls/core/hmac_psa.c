#include <psa/crypto.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <stdlib.h>
#include <string.h>
#include <kernel/panic.h>


#if defined(MBEDTLS_PSA_CRYPTO_C)

struct psa_hmac_ctx {
	struct crypto_mac_ctx ctx;
	psa_mac_operation_t operation;
	psa_algorithm_t alg;
	psa_key_id_t key_id;
};

static TEE_Result psa_hmac_init(struct crypto_mac_ctx *ctx,
			     const uint8_t *key, size_t len)
{
	struct psa_hmac_ctx *pctx = (struct psa_hmac_ctx *)ctx;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status;

	psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
	psa_set_key_bits(&attr, len * 8);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
	psa_set_key_algorithm(&attr, pctx->alg);
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);

	status = psa_import_key(&attr, key, len, &pctx->key_id);
	if (status != PSA_SUCCESS)
		return TEE_ERROR_GENERIC;

	status = psa_mac_sign_setup(&pctx->operation, pctx->key_id, pctx->alg);
	if (status != PSA_SUCCESS)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result psa_hmac_update(struct crypto_mac_ctx *ctx,
			       const uint8_t *data, size_t len)
{
	struct psa_hmac_ctx *pctx = (struct psa_hmac_ctx *)ctx;
	psa_status_t status = psa_mac_update(&pctx->operation, data, len);
	return status == PSA_SUCCESS ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

static TEE_Result psa_hmac_final(struct crypto_mac_ctx *ctx,
			      uint8_t *digest, size_t digest_len)
{
	struct psa_hmac_ctx *pctx = (struct psa_hmac_ctx *)ctx;
	psa_status_t status = psa_mac_sign_finish(&pctx->operation, digest, digest_len, NULL);
	psa_destroy_key(pctx->key_id);
	pctx->key_id = 0;
	return status == PSA_SUCCESS ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

static void psa_hmac_free_ctx(struct crypto_mac_ctx *ctx)
{
	struct psa_hmac_ctx *pctx = (struct psa_hmac_ctx *)ctx;
	psa_mac_abort(&pctx->operation);
	if (pctx->key_id)
		psa_destroy_key(pctx->key_id);
	free(pctx);
}

static void psa_hmac_copy_state(struct crypto_mac_ctx *dst,
			     struct crypto_mac_ctx *src)
{
	(void)dst;
	(void)src;
	panic("psa_hmac_copy_state not supported");
}

static const struct crypto_mac_ops psa_hmac_ops = {
	.init = psa_hmac_init,
	.update = psa_hmac_update,
	.final = psa_hmac_final,
	.free_ctx = psa_hmac_free_ctx,
	.copy_state = psa_hmac_copy_state,
};

TEE_Result crypto_mac_alloc_ctx(void **ctx_ret, uint32_t algo)
{
	struct psa_hmac_ctx *pctx = calloc(1, sizeof(*pctx));
	if (!pctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	switch (algo) {
	case TEE_ALG_HMAC_SHA1:
		pctx->alg = PSA_ALG_HMAC(PSA_ALG_SHA_1);
		break;
	case TEE_ALG_HMAC_SHA224:
		pctx->alg = PSA_ALG_HMAC(PSA_ALG_SHA_224);
		break;
	case TEE_ALG_HMAC_SHA256:
		pctx->alg = PSA_ALG_HMAC(PSA_ALG_SHA_256);
		break;
	case TEE_ALG_HMAC_SHA384:
		pctx->alg = PSA_ALG_HMAC(PSA_ALG_SHA_384);
		break;
	case TEE_ALG_HMAC_SHA512:
		pctx->alg = PSA_ALG_HMAC(PSA_ALG_SHA_512);
		break;
	default:
		free(pctx);
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	pctx->ctx.ops = &psa_hmac_ops;
	*ctx_ret = (void *)&pctx->ctx;
	return TEE_SUCCESS;
}

#endif

// SPDX-License-Identifier: BSD-2-Clause
#include <psa/crypto.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <stdlib.h>
#include <string.h>
#include <kernel/panic.h>

#if defined(MBEDTLS_PSA_CRYPTO_C)

struct psa_des_ctx {
	struct crypto_cipher_ctx ctx;
	psa_key_id_t key_id;
	psa_cipher_operation_t operation;
	psa_algorithm_t algo;
	uint8_t iv[8];
	size_t iv_len;
};

static TEE_Result psa_des_init(struct crypto_cipher_ctx *ctx,
				TEE_OperationMode mode,
				const uint8_t *key1, size_t key1_len,
				const uint8_t *key2 __unused, size_t key2_len __unused,
				const uint8_t *iv, size_t iv_len)
{
	struct psa_des_ctx *pctx = container_of(ctx, struct psa_des_ctx, ctx);
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status;

//	pctx->alg = (iv_len > 0) ? PSA_ALG_CBC_NO_PADDING : PSA_ALG_ECB_NO_PADDING;
	pctx->iv_len = iv_len;
	memcpy(pctx->iv, iv, iv_len);

	psa_set_key_type(&attr, PSA_KEY_TYPE_DES);
	psa_set_key_bits(&attr, key1_len * 8);
	psa_set_key_algorithm(&attr, pctx->algo);
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&attr,
		mode == TEE_MODE_ENCRYPT ?
			PSA_KEY_USAGE_ENCRYPT :
			PSA_KEY_USAGE_DECRYPT);

	status = psa_import_key(&attr, key1, key1_len, &pctx->key_id);
	if (status != PSA_SUCCESS)
		return TEE_ERROR_GENERIC;

	if (mode == TEE_MODE_ENCRYPT)
		status = psa_cipher_encrypt_setup(&pctx->operation, pctx->key_id, pctx->algo);
	else
		status = psa_cipher_decrypt_setup(&pctx->operation, pctx->key_id, pctx->algo);

	if (status != PSA_SUCCESS)
		return TEE_ERROR_GENERIC;

	if (pctx->algo == PSA_ALG_CBC_NO_PADDING) {
		status = psa_cipher_set_iv(&pctx->operation, iv, iv_len);
		if (status != PSA_SUCCESS)
			return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static TEE_Result psa_des_update(struct crypto_cipher_ctx *ctx, bool last_block __unused,
				 const uint8_t *data, size_t len, uint8_t *dst)
{
	struct psa_des_ctx *pctx = (struct psa_des_ctx *)ctx;
	psa_status_t status;
	size_t out_len = 0;

	status = psa_cipher_update(&pctx->operation, data, len, dst, len, &out_len);
	if (status != PSA_SUCCESS)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static void psa_des_final(struct crypto_cipher_ctx *ctx)
{
	struct psa_des_ctx *pctx = (struct psa_des_ctx *)ctx;
	uint8_t dummy[16];
	size_t out_len;

	psa_cipher_finish(&pctx->operation, dummy, sizeof(dummy), &out_len);
	psa_cipher_abort(&pctx->operation);
	psa_destroy_key(pctx->key_id);
	pctx->key_id = 0;
}

static void psa_des_free_ctx(struct crypto_cipher_ctx *ctx)
{
	struct psa_des_ctx *pctx = (struct psa_des_ctx *)ctx;

	psa_cipher_abort(&pctx->operation);
	if (pctx->key_id)
		psa_destroy_key(pctx->key_id);

	free(pctx);
}

static void psa_des_copy_state(struct crypto_cipher_ctx *dst,
			       struct crypto_cipher_ctx *src)
{
	(void)dst;
	(void)src;
	panic("copy_state not supported with PSA");
}

static const struct crypto_cipher_ops psa_des_ops = {
	.init = psa_des_init,
	.update = psa_des_update,
	.final = psa_des_final,
	.free_ctx = psa_des_free_ctx,
	.copy_state = psa_des_copy_state,
};
static TEE_Result cipher_alloc_wrapper(struct crypto_cipher_ctx **ctx_ret, uint32_t algo)
{
	psa_crypto_init();
	if (!ctx_ret) { EMSG("cipher_alloc_wrapper: ctx_ret is NULL"); return TEE_ERROR_BAD_PARAMETERS; }
	struct psa_des_ctx *c = NULL;

	c = calloc(1, sizeof(*c));
	if (!c) {
		EMSG("out of memory");
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	c->algo = algo;
	c->ctx.ops = &psa_des_ops;
	*ctx_ret = &c->ctx;
	return TEE_SUCCESS;
}
TEE_Result crypto_des_ecb_alloc_ctx(struct crypto_cipher_ctx **ctx)
{
	return cipher_alloc_wrapper(ctx, PSA_ALG_ECB_NO_PADDING);
}

TEE_Result crypto_des_cbc_alloc_ctx(struct crypto_cipher_ctx **ctx)
{
	return cipher_alloc_wrapper(ctx, PSA_ALG_CBC_NO_PADDING);
}

TEE_Result crypto_des3_ecb_alloc_ctx(struct crypto_cipher_ctx **ctx)
{
	return cipher_alloc_wrapper(ctx, PSA_ALG_ECB_NO_PADDING);
}

TEE_Result crypto_des3_cbc_alloc_ctx(struct crypto_cipher_ctx **ctx)
{
	return cipher_alloc_wrapper(ctx, PSA_ALG_CBC_NO_PADDING);
}

#endif // MBEDTLS_PSA_CRYPTO_C

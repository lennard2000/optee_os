#include "psa/crypto.h"
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <stdlib.h>
#include <string.h>
#include <kernel/panic.h>
#include <tee/tee_cryp_utl.h>

#if defined(MBEDTLS_PSA_CRYPTO_C)
#define MBEDTLS_PSA_BUILTIN_HASH
struct psa_hash_ctx {
	struct crypto_hash_ctx hash_ctx;
	psa_hash_operation_t operation;
	psa_algorithm_t alg;
};

static const struct crypto_hash_ops mbed_hash_ops;
static struct psa_hash_ctx *to_hash_ctx(struct crypto_hash_ctx *ctx){
	assert(ctx);
	return container_of(ctx, struct psa_hash_ctx, hash_ctx);
}
static TEE_Result hash_init_wrapper(struct crypto_hash_ctx *ctx)
{
	to_hash_ctx(ctx);
	return TEE_SUCCESS;
}

static TEE_Result psa_hash_update_wrapper(struct crypto_hash_ctx *ctx,
			       const uint8_t *data, size_t len)
{
	struct psa_hash_ctx *pctx = to_hash_ctx(ctx);
	psa_status_t status = psa_hash_update(&pctx->operation, data, len);
	return status == PSA_SUCCESS ? TEE_SUCCESS : TEE_ERROR_GENERIC;
	return TEE_SUCCESS;
}

static TEE_Result psa_hash_final_wrapper(struct crypto_hash_ctx *ctx,
			      uint8_t *digest, size_t digest_len)
{
	struct psa_hash_ctx *pctx = to_hash_ctx(ctx);
	psa_status_t status;
	status = psa_hash_finish(&pctx->operation, digest, digest_len, NULL);
	return status == PSA_SUCCESS ? TEE_SUCCESS : TEE_ERROR_GENERIC;
	return TEE_SUCCESS;
}

static void psa_hash_free_ctx(struct crypto_hash_ctx *ctx)
{
	struct psa_hash_ctx *pctx = to_hash_ctx(ctx);
	psa_hash_abort(&pctx->operation);
	free(pctx);
}

static void psa_hash_copy_state(struct crypto_hash_ctx *dst,
			    struct crypto_hash_ctx *src)
{
	(void)dst;
	(void)src;
	panic("psa_hash_copy_state not supported");
}

static const struct crypto_hash_ops psa_hash_ops = {
	.init = hash_init_wrapper,
	.update = psa_hash_update_wrapper,
	.final = psa_hash_final_wrapper,
	.free_ctx = psa_hash_free_ctx,
	.copy_state = psa_hash_copy_state,
};

static TEE_Result hash_alloc_wrapper(struct crypto_hash_ctx **ctx_ret, uint32_t algo)
{

	psa_crypto_init();
	int mbed_res = 0;
	struct psa_hash_ctx *hc = NULL;

	hc = calloc(1, sizeof(*hc));
	if (!hc)
		return TEE_ERROR_OUT_OF_MEMORY;
	hc->alg = algo;
	hc->hash_ctx.ops = &psa_hash_ops;
	psa_status_t status = psa_hash_setup(&hc->operation, hc->alg);
	if (status != PSA_SUCCESS) {
		free(hc);
		return TEE_ERROR_GENERIC;
		}
	*ctx_ret = &hc->hash_ctx;

	return TEE_SUCCESS;
}

TEE_Result crypto_md5_alloc_ctx(struct crypto_hash_ctx **ctx)
{
	return hash_alloc_wrapper(ctx, PSA_ALG_MD5);
}

TEE_Result crypto_sha1_alloc_ctx(struct crypto_hash_ctx **ctx)
{
	return hash_alloc_wrapper(ctx, PSA_ALG_SHA_1);
}

TEE_Result crypto_sha224_alloc_ctx(struct crypto_hash_ctx **ctx)
{
	return hash_alloc_wrapper(ctx, PSA_ALG_SHA_224);
}

TEE_Result crypto_sha256_alloc_ctx(struct crypto_hash_ctx **ctx)
{
	return hash_alloc_wrapper(ctx, PSA_ALG_SHA_256);
}

TEE_Result crypto_sha384_alloc_ctx(struct crypto_hash_ctx **ctx)
{
	return hash_alloc_wrapper(ctx, PSA_ALG_SHA_384);
}

TEE_Result crypto_sha512_alloc_ctx(struct crypto_hash_ctx **ctx)
{
	return hash_alloc_wrapper(ctx, PSA_ALG_SHA_512);
}

#endif
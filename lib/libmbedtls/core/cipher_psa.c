
#include <psa/crypto.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <stdlib.h>
#include <string.h>
#include <kernel/panic.h>

#if defined(MBEDTLS_PSA_CRYPTO_C)

struct psa_cipher_ctx {
    struct crypto_cipher_ctx ctx;
     psa_cipher_operation_t operation;
    mbedtls_svc_key_id_t key;
    psa_algorithm_t algo;
    uint8_t iv[PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE];
    size_t iv_len;
    psa_key_attributes_t key_attr;
    mbedtls_operation_t mbed_mode
};

static TEE_Result cipher_init(struct crypto_cipher_ctx *ctx,
				    TEE_OperationMode mode, const uint8_t *key1,
				    size_t key1_len,
				    const uint8_t *key2 __unused,
				    size_t key2_len __unused,
				    const uint8_t *iv __unused,
				    size_t iv_len  __unused)
{
	if (!ctx) { EMSG("cipher_init: ctx is NULL"); return TEE_ERROR_BAD_PARAMETERS; }
    struct psa_cipher_ctx *c = container_of(ctx, struct psa_cipher_ctx, ctx);
      if (c->algo == 0) {
	c->algo = PSA_ALG_ECB_NO_PADDING;
	EMSG("cipher_init: invalid algorithm");
    }
    c->operation = psa_cipher_operation_init();
    if (!ctx || !key1 || key1_len == 0) {
        EMSG("cipher_init: invalid parameters");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    psa_reset_key_attributes(&c->key_attr);

    psa_set_key_algorithm(&c->key_attr, c->algo);
    psa_set_key_type(&c->key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&c->key_attr, key1_len * 8);

    if (mode == TEE_MODE_ENCRYPT) {
		c->mbed_mode = MBEDTLS_ENCRYPT;
		 psa_set_key_usage_flags(&c->key_attr, PSA_KEY_USAGE_ENCRYPT);

	} else {
		c->mbed_mode = MBEDTLS_DECRYPT;
		EMSG("decrypt");
		 psa_set_key_usage_flags(&c->key_attr, PSA_KEY_USAGE_DECRYPT);
	}
	 psa_status_t status = psa_import_key(&c->key_attr, key1, key1_len, &c->key);
	 if(status != PSA_SUCCESS) {
		 EMSG("cipher_init: import_key failed");
	 }
	 if( c->mbed_mode == MBEDTLS_ENCRYPT){
		status = psa_cipher_encrypt_setup(&c->operation,c->key, c->algo);
	 }else{
		 status = psa_cipher_decrypt_setup(&c->operation,c->key, c->algo);
	 }
	 if(status != PSA_SUCCESS) {
		 EMSG("cipher_init: psa_cipher_encrypt_setup failed");
	 }
	 if(c->algo == PSA_ALG_CTR || c->algo == PSA_ALG_CBC_NO_PADDING) {
		 status = psa_cipher_set_iv(&c->operation, c->iv, c->iv_len);
		 if(status != PSA_SUCCESS) {
			 EMSG("cipher_init: psa_cipher_set_iv failed");
		 }
	 }

    return TEE_SUCCESS;
}

static TEE_Result cipher_update(struct crypto_cipher_ctx *ctx,
                                bool last_block __unused,
                                const uint8_t *data, size_t len,
                                uint8_t *dst)
{
	if (!ctx) { EMSG("cipher_update: ctx is NULL"); return TEE_ERROR_BAD_PARAMETERS; }
	if (!dst) { EMSG("cipher_update: dst is NULL"); return TEE_ERROR_BAD_PARAMETERS; }
    struct psa_cipher_ctx *c = container_of(ctx, struct psa_cipher_ctx, ctx);

    if (!c || !data || !dst) {
        EMSG("cipher_update: invalid parameters");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    size_t out_len = 0;
    psa_status_t status = psa_cipher_update(&c->operation, data, len, dst, len, &out_len);
    if (status != PSA_SUCCESS) {
        EMSG("cipher_update: psa_cipher_update failed (0x%x)", status);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static void cipher_free_ctx(struct crypto_cipher_ctx *ctx)
{
    struct psa_cipher_ctx *c = container_of(ctx, struct psa_cipher_ctx, ctx);

    if (!c) {
        EMSG("cipher_free_ctx: null context");
        return;
    }

    psa_destroy_key(c->key);
    memset(c, 0, sizeof(*c));

}

static void cipher_final(struct crypto_cipher_ctx *ctx)
{
	struct psa_cipher_ctx *c = container_of(ctx, struct psa_cipher_ctx, ctx);

    if (!c) {
        EMSG("cipher_free_ctx: null context");
        return;
    }

    psa_destroy_key(c->key);
}

static void cipher_copy_state(struct crypto_cipher_ctx *dst_ctx,
                              struct crypto_cipher_ctx *src_ctx)
{
    struct psa_cipher_ctx *dst = container_of(dst_ctx, struct psa_cipher_ctx, ctx);
    struct psa_cipher_ctx *src = container_of(src_ctx, struct psa_cipher_ctx, ctx);

    if (!dst || !src) {
        EMSG("cipher_copy_state: invalid context(s)");
        return;
    }

    memcpy(dst, src, sizeof(*dst));
}

const struct crypto_cipher_ops psa_cipher_ops = {
    .init = cipher_init,
    .update = cipher_update,
	.final = cipher_final,
    .free_ctx = cipher_free_ctx,
    .copy_state = cipher_copy_state,
};
static TEE_Result cipher_alloc_wrapper(struct crypto_cipher_ctx **ctx_ret, uint32_t algo)
{
	psa_crypto_init();
	if (!ctx_ret) { EMSG("cipher_alloc_wrapper: ctx_ret is NULL"); return TEE_ERROR_BAD_PARAMETERS; }
	struct psa_cipher_ctx *c = NULL;

	c = calloc(1, sizeof(*c));
	if (!c) {
		EMSG("out of memory");
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	c->algo = algo;
	c->ctx.ops = &psa_cipher_ops;
	*ctx_ret = &c->ctx;
	return TEE_SUCCESS;
}

TEE_Result crypto_aes_cbc_alloc_ctx(struct crypto_cipher_ctx **ctx_ret)
{
	return cipher_alloc_wrapper(ctx_ret, PSA_ALG_CBC_NO_PADDING);
}

TEE_Result crypto_aes_ctr_alloc_ctx(struct crypto_cipher_ctx **ctx_ret)
{
	return cipher_alloc_wrapper(ctx_ret, PSA_ALG_CTR);
}

TEE_Result crypto_aes_ecb_alloc_ctx(struct crypto_cipher_ctx **ctx_ret)
{
	return cipher_alloc_wrapper(ctx_ret, PSA_ALG_ECB_NO_PADDING);
}

#endif /* MBEDTLS_PSA_CRYPTO_C */
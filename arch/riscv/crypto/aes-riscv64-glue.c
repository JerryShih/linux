// SPDX-License-Identifier: GPL-2.0-only
/*
 * Port of the OpenSSL AES implementation for RISC-V
 *
 * Copyright (C) 2023 VRULL GmbH
 * Author: Heiko Stuebner <heiko.stuebner@vrull.eu>
 *
 * Copyright (C) 2023 SiFive, Inc.
 * Author: Jerry Shih <jerry.shih@sifive.com>
 */

#include <asm/simd.h>
#include <asm/vector.h>
#include <crypto/aes.h>
#include <crypto/internal/cipher.h>
#include <crypto/internal/simd.h>
#include <linux/crypto.h>
#include <linux/module.h>
#include <linux/types.h>

#include "aes-riscv64-glue.h"

/*
 * aes cipher using zvkned vector crypto extension
 *
 * All zvkned-based functions use encryption expending keys for both encryption
 * and decryption.
 */
void rv64i_zvkned_encrypt(const u8 *in, u8 *out, const struct aes_key *key);
void rv64i_zvkned_decrypt(const u8 *in, u8 *out, const struct aes_key *key);

static inline int aes_round_num(unsigned int keylen)
{
	switch (keylen) {
	case AES_KEYSIZE_128:
		return 10;
	case AES_KEYSIZE_192:
		return 12;
	case AES_KEYSIZE_256:
		return 14;
	default:
		return 0;
	}
}

int riscv64_aes_setkey(struct riscv64_aes_ctx *ctx, const u8 *key,
		       unsigned int keylen)
{
	/*
	 * The RISC-V AES vector crypto key expending doesn't support AES-192.
	 * We just use the generic software key expending here to simplify the key
	 * expending flow.
	 */
	u32 aes_rounds;
	u32 key_length;
	int ret;

	ret = aes_expandkey(&ctx->fallback_ctx, key, keylen);
	if (ret < 0)
		return -EINVAL;

	/*
	 * Copy the key from `crypto_aes_ctx` to `aes_key` for zvkned-based AES
	 * implementations.
	 */
	aes_rounds = aes_round_num(keylen);
	ctx->key.rounds = aes_rounds;
	key_length = AES_BLOCK_SIZE * (aes_rounds + 1);
	memcpy(ctx->key.key, ctx->fallback_ctx.key_enc, key_length);

	return 0;
}

void riscv64_aes_encrypt_zvkned(const struct riscv64_aes_ctx *ctx, u8 *dst,
				const u8 *src)
{
	if (crypto_simd_usable()) {
		kernel_vector_begin();
		rv64i_zvkned_encrypt(src, dst, &ctx->key);
		kernel_vector_end();
	} else {
		aes_encrypt(&ctx->fallback_ctx, dst, src);
	}
}

void riscv64_aes_decrypt_zvkned(const struct riscv64_aes_ctx *ctx, u8 *dst,
				const u8 *src)
{
	if (crypto_simd_usable()) {
		kernel_vector_begin();
		rv64i_zvkned_decrypt(src, dst, &ctx->key);
		kernel_vector_end();
	} else {
		aes_decrypt(&ctx->fallback_ctx, dst, src);
	}
}

static int aes_setkey(struct crypto_tfm *tfm, const u8 *key,
		      unsigned int keylen)
{
	struct riscv64_aes_ctx *ctx = crypto_tfm_ctx(tfm);

	return riscv64_aes_setkey(ctx, key, keylen);
}

static void aes_encrypt_zvkned(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
	const struct riscv64_aes_ctx *ctx = crypto_tfm_ctx(tfm);

	riscv64_aes_encrypt_zvkned(ctx, dst, src);
}

static void aes_decrypt_zvkned(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
	const struct riscv64_aes_ctx *ctx = crypto_tfm_ctx(tfm);

	riscv64_aes_decrypt_zvkned(ctx, dst, src);
}

static struct crypto_alg riscv64_aes_alg_zvkned = {
	.cra_name = "aes",
	.cra_driver_name = "aes-riscv64-zvkned",
	.cra_module = THIS_MODULE,
	.cra_priority = 300,
	.cra_flags = CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize = AES_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct riscv64_aes_ctx),
	.cra_cipher = {
		.cia_min_keysize = AES_MIN_KEY_SIZE,
		.cia_max_keysize = AES_MAX_KEY_SIZE,
		.cia_setkey = aes_setkey,
		.cia_encrypt = aes_encrypt_zvkned,
		.cia_decrypt = aes_decrypt_zvkned,
	},
};

static inline bool check_aes_ext(void)
{
	return riscv_isa_extension_available(NULL, ZVKNED) &&
	       riscv_vector_vlen() >= 128;
}

static int __init riscv64_aes_mod_init(void)
{
	if (check_aes_ext())
		return crypto_register_alg(&riscv64_aes_alg_zvkned);

	return -ENODEV;
}

static void __exit riscv64_aes_mod_fini(void)
{
	if (check_aes_ext())
		crypto_unregister_alg(&riscv64_aes_alg_zvkned);
}

module_init(riscv64_aes_mod_init);
module_exit(riscv64_aes_mod_fini);

MODULE_DESCRIPTION("AES (RISC-V accelerated)");
MODULE_AUTHOR("Heiko Stuebner <heiko.stuebner@vrull.eu>");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("aes");

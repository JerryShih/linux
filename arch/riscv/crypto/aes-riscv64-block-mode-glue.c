// SPDX-License-Identifier: GPL-2.0-only
/*
 * Port of the OpenSSL AES block mode implementations for RISC-V
 *
 * Copyright (C) 2023 SiFive, Inc.
 * Author: Jerry Shih <jerry.shih@sifive.com>
 */

#include <asm/simd.h>
#include <asm/vector.h>
#include <crypto/aes.h>
#include <crypto/ctr.h>
#include <crypto/xts.h>
#include <crypto/internal/cipher.h>
#include <crypto/internal/simd.h>
#include <crypto/internal/skcipher.h>
#include <crypto/scatterwalk.h>
#include <linux/crypto.h>
#include <linux/math.h>
#include <linux/minmax.h>
#include <linux/module.h>
#include <linux/types.h>

#include "aes-riscv64-glue.h"

#define AES_BLOCK_VALID_SIZE_MASK (~(AES_BLOCK_SIZE - 1))
#define AES_BLOCK_REMAINING_SIZE_MASK (AES_BLOCK_SIZE - 1)

struct riscv64_aes_xts_ctx {
	struct riscv64_aes_ctx ctx1;
	struct riscv64_aes_ctx ctx2;
};

/* aes cbc block mode using zvkned vector crypto extension */
void rv64i_zvkned_cbc_encrypt(const u8 *in, u8 *out, size_t length,
			      const struct aes_key *key, u8 *ivec);
void rv64i_zvkned_cbc_decrypt(const u8 *in, u8 *out, size_t length,
			      const struct aes_key *key, u8 *ivec);
/* aes ecb block mode using zvkned vector crypto extension */
void rv64i_zvkned_ecb_encrypt(const u8 *in, u8 *out, size_t length,
			      const struct aes_key *key);
void rv64i_zvkned_ecb_decrypt(const u8 *in, u8 *out, size_t length,
			      const struct aes_key *key);

/* aes ctr block mode using zvkb and zvkned vector crypto extension */
/* This func operates on 32-bit counter. Caller has to handle the overflow. */
void rv64i_zvkb_zvkned_ctr32_encrypt_blocks(const u8 *in, u8 *out,
					    size_t length,
					    const struct aes_key *key,
					    u8 *ivec);

/* aes xts block mode using zvbb, zvkg and zvkned vector crypto extension */
void rv64i_zvbb_zvkg_zvkned_aes_xts_encrypt(const u8 *in, u8 *out,
					    size_t length,
					    const struct aes_key *key, u8 *iv,
					    int update_iv);
void rv64i_zvbb_zvkg_zvkned_aes_xts_decrypt(const u8 *in, u8 *out,
					    size_t length,
					    const struct aes_key *key, u8 *iv,
					    int update_iv);

typedef void (*aes_xts_func)(const u8 *in, u8 *out, size_t length,
			     const struct aes_key *key, u8 *iv, int update_iv);

/* ecb */
static int aes_setkey(struct crypto_skcipher *tfm, const u8 *in_key,
		      unsigned int key_len)
{
	struct riscv64_aes_ctx *ctx = crypto_skcipher_ctx(tfm);

	return riscv64_aes_setkey(ctx, in_key, key_len);
}

static int ecb_encrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct riscv64_aes_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	unsigned int nbytes;
	int err;

	/* If we have error here, the `nbytes` will be zero. */
	err = skcipher_walk_virt(&walk, req, false);
	while ((nbytes = walk.nbytes)) {
		kernel_vector_begin();
		rv64i_zvkned_ecb_encrypt(walk.src.virt.addr, walk.dst.virt.addr,
					 nbytes & AES_BLOCK_VALID_SIZE_MASK,
					 &ctx->key);
		kernel_vector_end();
		err = skcipher_walk_done(
			&walk, nbytes & AES_BLOCK_REMAINING_SIZE_MASK);
	}

	return err;
}

static int ecb_decrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct riscv64_aes_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	unsigned int nbytes;
	int err;

	err = skcipher_walk_virt(&walk, req, false);
	while ((nbytes = walk.nbytes)) {
		kernel_vector_begin();
		rv64i_zvkned_ecb_decrypt(walk.src.virt.addr, walk.dst.virt.addr,
					 nbytes & AES_BLOCK_VALID_SIZE_MASK,
					 &ctx->key);
		kernel_vector_end();
		err = skcipher_walk_done(
			&walk, nbytes & AES_BLOCK_REMAINING_SIZE_MASK);
	}

	return err;
}

/* cbc */
static int cbc_encrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct riscv64_aes_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	unsigned int nbytes;
	int err;

	err = skcipher_walk_virt(&walk, req, false);
	while ((nbytes = walk.nbytes)) {
		kernel_vector_begin();
		rv64i_zvkned_cbc_encrypt(walk.src.virt.addr, walk.dst.virt.addr,
					 nbytes & AES_BLOCK_VALID_SIZE_MASK,
					 &ctx->key, walk.iv);
		kernel_vector_end();
		err = skcipher_walk_done(
			&walk, nbytes & AES_BLOCK_REMAINING_SIZE_MASK);
	}

	return err;
}

static int cbc_decrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct riscv64_aes_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	unsigned int nbytes;
	int err;

	err = skcipher_walk_virt(&walk, req, false);
	while ((nbytes = walk.nbytes)) {
		kernel_vector_begin();
		rv64i_zvkned_cbc_decrypt(walk.src.virt.addr, walk.dst.virt.addr,
					 nbytes & AES_BLOCK_VALID_SIZE_MASK,
					 &ctx->key, walk.iv);
		kernel_vector_end();
		err = skcipher_walk_done(
			&walk, nbytes & AES_BLOCK_REMAINING_SIZE_MASK);
	}

	return err;
}

/* ctr */
static int ctr_encrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct riscv64_aes_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	unsigned int ctr32;
	unsigned int nbytes;
	unsigned int blocks;
	unsigned int current_blocks;
	unsigned int current_length;
	int err;

	/* the ctr iv uses big endian */
	ctr32 = get_unaligned_be32(req->iv + 12);
	err = skcipher_walk_virt(&walk, req, false);
	while ((nbytes = walk.nbytes)) {
		if (nbytes != walk.total) {
			nbytes &= AES_BLOCK_VALID_SIZE_MASK;
			blocks = nbytes / AES_BLOCK_SIZE;
		} else {
			/* This is the last walk. We should handle the tail data. */
			blocks = (nbytes + (AES_BLOCK_SIZE - 1)) /
				 AES_BLOCK_SIZE;
		}
		ctr32 += blocks;

		kernel_vector_begin();
		/*
		 * The `if` block below detects the overflow, which is then handled by
		 * limiting the amount of blocks to the exact overflow point.
		 */
		if (ctr32 >= blocks) {
			rv64i_zvkb_zvkned_ctr32_encrypt_blocks(
				walk.src.virt.addr, walk.dst.virt.addr, nbytes,
				&ctx->key, req->iv);
		} else {
			/* use 2 ctr32 function calls for overflow case */
			current_blocks = blocks - ctr32;
			current_length =
				min(nbytes, current_blocks * AES_BLOCK_SIZE);
			rv64i_zvkb_zvkned_ctr32_encrypt_blocks(
				walk.src.virt.addr, walk.dst.virt.addr,
				current_length, &ctx->key, req->iv);
			crypto_inc(req->iv, 12);

			if (ctr32) {
				rv64i_zvkb_zvkned_ctr32_encrypt_blocks(
					walk.src.virt.addr +
						current_blocks * AES_BLOCK_SIZE,
					walk.dst.virt.addr +
						current_blocks * AES_BLOCK_SIZE,
					nbytes - current_length, &ctx->key,
					req->iv);
			}
		}
		kernel_vector_end();

		err = skcipher_walk_done(&walk, walk.nbytes - nbytes);
	}

	return err;
}

/* xts */
static int xts_setkey(struct crypto_skcipher *tfm, const u8 *in_key,
		      unsigned int key_len)
{
	struct riscv64_aes_xts_ctx *ctx = crypto_skcipher_ctx(tfm);
	unsigned int xts_single_key_len = key_len / 2;
	int ret;

	ret = xts_verify_key(tfm, in_key, key_len);
	if (ret)
		return ret;
	ret = riscv64_aes_setkey(&ctx->ctx1, in_key, xts_single_key_len);
	if (ret)
		return ret;
	return riscv64_aes_setkey(&ctx->ctx2, in_key + xts_single_key_len,
				  xts_single_key_len);
}

static int xts_crypt(struct skcipher_request *req, aes_xts_func func)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct riscv64_aes_xts_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_request sub_req;
	struct scatterlist sg_src[2], sg_dst[2];
	struct scatterlist *src, *dst;
	struct skcipher_walk walk;
	unsigned int walk_size = crypto_skcipher_walksize(tfm);
	unsigned int tail_bytes;
	unsigned int head_bytes;
	unsigned int nbytes;
	unsigned int update_iv = 1;
	int err;

	/* xts input size should be bigger than AES_BLOCK_SIZE */
	if (req->cryptlen < AES_BLOCK_SIZE)
		return -EINVAL;

	/*
	 * The tail size should be small than walk_size. Thus, we could make sure the
	 * walk size for tail elements could be bigger than AES_BLOCK_SIZE.
	 */
	if (req->cryptlen <= walk_size) {
		tail_bytes = req->cryptlen;
		head_bytes = 0;
	} else {
		if (req->cryptlen & AES_BLOCK_REMAINING_SIZE_MASK) {
			tail_bytes = req->cryptlen &
				     AES_BLOCK_REMAINING_SIZE_MASK;
			tail_bytes = walk_size + tail_bytes - AES_BLOCK_SIZE;
			head_bytes = req->cryptlen - tail_bytes;
		} else {
			tail_bytes = 0;
			head_bytes = req->cryptlen;
		}
	}

	riscv64_aes_encrypt_zvkned(&ctx->ctx2, req->iv, req->iv);

	if (head_bytes && tail_bytes) {
		skcipher_request_set_tfm(&sub_req, tfm);
		skcipher_request_set_callback(
			&sub_req, skcipher_request_flags(req), NULL, NULL);
		skcipher_request_set_crypt(&sub_req, req->src, req->dst,
					   head_bytes, req->iv);
		req = &sub_req;
	}

	if (head_bytes) {
		err = skcipher_walk_virt(&walk, req, false);
		while ((nbytes = walk.nbytes)) {
			if (nbytes == walk.total)
				update_iv = (tail_bytes > 0);

			nbytes &= AES_BLOCK_VALID_SIZE_MASK;
			kernel_vector_begin();
			func(walk.src.virt.addr, walk.dst.virt.addr, nbytes,
			     &ctx->ctx1.key, req->iv, update_iv);
			kernel_vector_end();

			err = skcipher_walk_done(&walk, walk.nbytes - nbytes);
		}
		if (err || !tail_bytes)
			return err;

		dst = src = scatterwalk_next(sg_src, &walk.in);
		if (req->dst != req->src)
			dst = scatterwalk_next(sg_dst, &walk.out);
		skcipher_request_set_crypt(req, src, dst, tail_bytes, req->iv);
	}

	/* tail */
	err = skcipher_walk_virt(&walk, req, false);
	if (err)
		return err;
	if (walk.nbytes != tail_bytes)
		return -EINVAL;
	kernel_vector_begin();
	func(walk.src.virt.addr, walk.dst.virt.addr, walk.nbytes,
	     &ctx->ctx1.key, req->iv, 0);
	kernel_vector_end();

	return skcipher_walk_done(&walk, 0);
}

static int xts_encrypt(struct skcipher_request *req)
{
	return xts_crypt(req, rv64i_zvbb_zvkg_zvkned_aes_xts_encrypt);
}

static int xts_decrypt(struct skcipher_request *req)
{
	return xts_crypt(req, rv64i_zvbb_zvkg_zvkned_aes_xts_decrypt);
}

static struct skcipher_alg riscv64_aes_alg_zvkned[] = { {
	.base = {
		.cra_name	= "ecb(aes)",
		.cra_driver_name = "ecb-aes-riscv64-zvkned",
		.cra_priority = 300,
		.cra_blocksize = AES_BLOCK_SIZE,
		.cra_ctxsize = sizeof(struct riscv64_aes_ctx),
		.cra_module = THIS_MODULE,
	},
	.min_keysize = AES_MIN_KEY_SIZE,
	.max_keysize = AES_MAX_KEY_SIZE,
	.walksize = AES_BLOCK_SIZE * 8,
	.setkey = aes_setkey,
	.encrypt = ecb_encrypt,
	.decrypt = ecb_decrypt,
}, {
	.base = {
		.cra_name = "cbc(aes)",
		.cra_driver_name = "cbc-aes-riscv64-zvkned",
		.cra_priority = 300,
		.cra_blocksize = AES_BLOCK_SIZE,
		.cra_ctxsize = sizeof(struct riscv64_aes_ctx),
		.cra_module = THIS_MODULE,
	},
	.min_keysize = AES_MIN_KEY_SIZE,
	.max_keysize = AES_MAX_KEY_SIZE,
	.ivsize = AES_BLOCK_SIZE,
	.walksize = AES_BLOCK_SIZE * 8,
	.setkey = aes_setkey,
	.encrypt = cbc_encrypt,
	.decrypt = cbc_decrypt,
} };

static struct skcipher_alg riscv64_aes_alg_zvkb_zvkned[] = { {
	.base = {
		.cra_name = "ctr(aes)",
		.cra_driver_name = "ctr-aes-riscv64-zvkb-zvkned",
		.cra_priority = 300,
		.cra_blocksize = 1,
		.cra_ctxsize = sizeof(struct riscv64_aes_ctx),
		.cra_module = THIS_MODULE,
	},
	.min_keysize = AES_MIN_KEY_SIZE,
	.max_keysize = AES_MAX_KEY_SIZE,
	.ivsize = AES_BLOCK_SIZE,
	.chunksize = AES_BLOCK_SIZE,
	.walksize = AES_BLOCK_SIZE * 8,
	.setkey = aes_setkey,
	.encrypt = ctr_encrypt,
	.decrypt = ctr_encrypt,
} };

static struct skcipher_alg riscv64_aes_alg_zvbb_zvkg_zvkned[] = { {
	.base = {
		.cra_name = "xts(aes)",
		.cra_driver_name = "xts-aes-riscv64-zvbb-zvkg-zvkned",
		.cra_priority = 300,
		.cra_blocksize = AES_BLOCK_SIZE,
		.cra_ctxsize = sizeof(struct riscv64_aes_xts_ctx),
		.cra_module = THIS_MODULE,
	},
	.min_keysize = AES_MIN_KEY_SIZE * 2,
	.max_keysize = AES_MAX_KEY_SIZE * 2,
	.ivsize = AES_BLOCK_SIZE,
	.chunksize = AES_BLOCK_SIZE,
	.walksize = AES_BLOCK_SIZE * 8,
	.setkey = xts_setkey,
	.encrypt = xts_encrypt,
	.decrypt = xts_decrypt,
} };

static int __init riscv64_aes_block_mod_init(void)
{
	int ret = -ENODEV;

	if (riscv_isa_extension_available(NULL, ZVKNED) &&
	    riscv_vector_vlen() >= 128) {
		ret = crypto_register_skciphers(
			riscv64_aes_alg_zvkned,
			ARRAY_SIZE(riscv64_aes_alg_zvkned));
		if (ret)
			return ret;

		if (riscv_isa_extension_available(NULL, ZVBB)) {
			ret = crypto_register_skciphers(
				riscv64_aes_alg_zvkb_zvkned,
				ARRAY_SIZE(riscv64_aes_alg_zvkb_zvkned));
			if (ret)
				goto unregister_zvkned;

			if (riscv_isa_extension_available(NULL, ZVKG)) {
				ret = crypto_register_skciphers(
					riscv64_aes_alg_zvbb_zvkg_zvkned,
					ARRAY_SIZE(
						riscv64_aes_alg_zvbb_zvkg_zvkned));
				if (ret)
					goto unregister_zvkb_zvkned;
			}
		}
	}

	return ret;

unregister_zvkb_zvkned:
	crypto_unregister_skciphers(riscv64_aes_alg_zvkb_zvkned,
				    ARRAY_SIZE(riscv64_aes_alg_zvkb_zvkned));
unregister_zvkned:
	crypto_unregister_skciphers(riscv64_aes_alg_zvkned,
				    ARRAY_SIZE(riscv64_aes_alg_zvkned));

	return ret;
}

static void __exit riscv64_aes_block_mod_fini(void)
{
	if (riscv_isa_extension_available(NULL, ZVKNED) &&
	    riscv_vector_vlen() >= 128) {
		crypto_unregister_skciphers(riscv64_aes_alg_zvkned,
					    ARRAY_SIZE(riscv64_aes_alg_zvkned));

		if (riscv_isa_extension_available(NULL, ZVBB)) {
			crypto_unregister_skciphers(
				riscv64_aes_alg_zvkb_zvkned,
				ARRAY_SIZE(riscv64_aes_alg_zvkb_zvkned));

			if (riscv_isa_extension_available(NULL, ZVKG)) {
				crypto_unregister_skciphers(
					riscv64_aes_alg_zvbb_zvkg_zvkned,
					ARRAY_SIZE(
						riscv64_aes_alg_zvbb_zvkg_zvkned));
			}
		}
	}
}

module_init(riscv64_aes_block_mod_init);
module_exit(riscv64_aes_block_mod_fini);

MODULE_DESCRIPTION("AES-ECB/CBC/CTR/XTS (RISC-V accelerated)");
MODULE_AUTHOR("Jerry Shih <jerry.shih@sifive.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("cbc(aes)");
MODULE_ALIAS_CRYPTO("ctr(aes)");
MODULE_ALIAS_CRYPTO("ecb(aes)");
MODULE_ALIAS_CRYPTO("xts(aes)");

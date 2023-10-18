/* SPDX-License-Identifier: GPL-2.0 */

#ifndef AES_RISCV64_GLUE_H
#define AES_RISCV64_GLUE_H

#include <crypto/aes.h>
#include <linux/types.h>

struct aes_key {
	u32 key[AES_MAX_KEYLENGTH_U32];
	u32 rounds;
};

struct riscv64_aes_ctx {
	struct aes_key key;
	struct crypto_aes_ctx fallback_ctx;
};

int riscv64_aes_setkey(struct riscv64_aes_ctx *ctx, const u8 *key,
		       unsigned int keylen);

void riscv64_aes_encrypt_zvkned(const struct riscv64_aes_ctx *ctx, u8 *dst,
				const u8 *src);

void riscv64_aes_decrypt_zvkned(const struct riscv64_aes_ctx *ctx, u8 *dst,
				const u8 *src);

#endif /* AES_RISCV64_GLUE_H */

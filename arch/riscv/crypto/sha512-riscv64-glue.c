// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Linux/riscv64 port of the OpenSSL SHA512 implementation for RISC-V 64
 *
 * Copyright (C) 2023 VRULL GmbH
 * Author: Heiko Stuebner <heiko.stuebner@vrull.eu>
 */

#include <asm/simd.h>
#include <asm/vector.h>
#include <linux/module.h>
#include <linux/types.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/simd.h>
#include <crypto/sha512_base.h>

/*
 * sha512 using zvkb and zvknhb vector crypto extension
 *
 * This asm function will just take the first 512-bit as the sha512 state from
 * the pointer to `struct sha512_state`.
 */
void sha512_block_data_order_zvkb_zvknhb(struct sha512_state *digest,
					 const u8 *data, int num_blks);

static int riscv64_sha512_update(struct shash_desc *desc, const u8 *data,
				 unsigned int len)
{
	int ret = 0;

	/*
	 * Make sure struct sha256_state begins directly with the SHA256
	 * 256-bit internal state, as this is what the asm function expect.
	 */
	BUILD_BUG_ON(offsetof(struct sha512_state, state) != 0);

	if (crypto_simd_usable()) {
		kernel_vector_begin();
		ret = sha512_base_do_update(
			desc, data, len, sha512_block_data_order_zvkb_zvknhb);
		kernel_vector_end();
	} else {
		ret = crypto_sha512_update(desc, data, len);
	}

	return ret;
}

static int riscv64_sha512_finup(struct shash_desc *desc, const u8 *data,
				unsigned int len, u8 *out)
{
	if (crypto_simd_usable()) {
		kernel_vector_begin();
		if (len)
			sha512_base_do_update(
				desc, data, len,
				sha512_block_data_order_zvkb_zvknhb);
		sha512_base_do_finalize(desc,
					sha512_block_data_order_zvkb_zvknhb);
		kernel_vector_end();

		return sha512_base_finish(desc, out);
	}

	return crypto_sha512_finup(desc, data, len, out);
}

static int riscv64_sha512_final(struct shash_desc *desc, u8 *out)
{
	return riscv64_sha512_finup(desc, NULL, 0, out);
}

static struct shash_alg sha512_alg[] = {
	{
		.digestsize = SHA512_DIGEST_SIZE,
		.init = sha512_base_init,
		.update = riscv64_sha512_update,
		.final = riscv64_sha512_final,
		.finup = riscv64_sha512_finup,
		.descsize = sizeof(struct sha512_state),
		.base.cra_name = "sha512",
		.base.cra_driver_name = "sha512-riscv64-zvkb-zvknhb",
		.base.cra_priority = 150,
		.base.cra_blocksize = SHA512_BLOCK_SIZE,
		.base.cra_module = THIS_MODULE,
	},
	{
		.digestsize = SHA384_DIGEST_SIZE,
		.init = sha384_base_init,
		.update = riscv64_sha512_update,
		.final = riscv64_sha512_final,
		.finup = riscv64_sha512_finup,
		.descsize = sizeof(struct sha512_state),
		.base.cra_name = "sha384",
		.base.cra_driver_name = "sha384-riscv64-zvkb-zvknhb",
		.base.cra_priority = 150,
		.base.cra_blocksize = SHA384_BLOCK_SIZE,
		.base.cra_module = THIS_MODULE,
	}
};

static inline bool check_sha512_ext(void)
{
	return riscv_isa_extension_available(NULL, ZVKNHB) &&
	       riscv_isa_extension_available(NULL, ZVKB) &&
	       riscv_vector_vlen() >= 128;
}

static int __init riscv64_sha512_mod_init(void)
{
	if (check_sha512_ext())
		return crypto_register_shashes(sha512_alg,
					       ARRAY_SIZE(sha512_alg));

	return -ENODEV;
}

static void __exit riscv64_sha512_mod_fini(void)
{
	if (check_sha512_ext())
		crypto_unregister_shashes(sha512_alg, ARRAY_SIZE(sha512_alg));
}

module_init(riscv64_sha512_mod_init);
module_exit(riscv64_sha512_mod_fini);

MODULE_DESCRIPTION("SHA-512 (RISC-V accelerated)");
MODULE_AUTHOR("Andy Polyakov <appro@openssl.org>");
MODULE_AUTHOR("Ard Biesheuvel <ard.biesheuvel@linaro.org>");
MODULE_AUTHOR("Heiko Stuebner <heiko.stuebner@vrull.eu>");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("sha384");
MODULE_ALIAS_CRYPTO("sha512");

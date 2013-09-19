/* crypto/rsa/rsa_gen.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */


/* NB: these functions have been "upgraded", the deprecated versions (which are
 * compatibility wrappers using these functions) are in rsa_depr.c.
 * - Geoff
 */

#include <stdio.h>
#include <time.h>
#include "cryptlib.h"
#include <openssl/bn.h>
#include <openssl/rsa.h>
#ifdef OPENSSL_FIPS
#include <openssl/fips.h>
#endif
#ifdef OPENSSL_CRYPTOCOP
#include <syslog.h>
#endif

#include "rsa_locl.h"

static int rsa_builtin_multi_prime_keygen(RSA *rsa, int bits, int num_primes, BIGNUM *e_value, BN_GENCB *cb);

/* NB: this wrapper would normally be placed in rsa_lib.c and the static
 * implementation would probably be in rsa_eay.c. Nonetheless, is kept here so
 * that we don't introduce a new linker dependency. Eg. any application that
 * wasn't previously linking object code related to key-generation won't have to
 * now just because key-generation is part of RSA_METHOD. */
int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e_value, BN_GENCB *cb)
	{
#ifdef OPENSSL_FIPS
	if (FIPS_mode() && !(rsa->meth->flags & RSA_FLAG_FIPS_METHOD)
			&& !(rsa->flags & RSA_FLAG_NON_FIPS_ALLOW))
		{
		RSAerr(RSA_F_RSA_GENERATE_KEY_EX, RSA_R_NON_FIPS_RSA_METHOD);
		return 0;
		}
#endif
	if(rsa->meth->rsa_keygen)
		return rsa->meth->rsa_keygen(rsa, bits, e_value, cb);
#ifdef OPENSSL_FIPS
	if (FIPS_mode())
		return FIPS_rsa_generate_key_ex(rsa, bits, e_value, cb);
#endif
	return rsa_builtin_multi_prime_keygen(rsa, bits, 2 /* num primes */, e_value, cb);
	}

int RSA_generate_multi_prime_key(RSA *rsa, int bits, int num_primes, BIGNUM *e_value, BN_GENCB *cb)
	{
	if((rsa->meth->flags & RSA_METHOD_FLAG_MULTI_PRIME_OK) &&
	   rsa->meth->rsa_multi_prime_keygen)
		{
		return rsa->meth->rsa_multi_prime_keygen(rsa, bits, num_primes, e_value, cb);
		}
	return rsa_builtin_multi_prime_keygen(rsa, bits, num_primes, e_value, cb);
	}

static int rsa_builtin_multi_prime_keygen(RSA *rsa, int bits, int num_primes, BIGNUM *e_value, BN_GENCB *cb)
	{
	BIGNUM *r0=NULL,*r1=NULL,*r2=NULL,*r3=NULL,*tmp;
	BIGNUM local_r0,local_d,local_p;
	BIGNUM *pr0,*d,*p;
	int prime_bits, ok= -1,n=0,i,j;
	BN_CTX *ctx=NULL;
#ifdef OPENSSL_CRYPTOCOP
	static int cryptocop_count;
#endif
	STACK_OF(RSA_additional_prime) *additional_primes = NULL;

	if (num_primes < 2)
		{
		ok = 0; /* we set our own err */
		RSAerr(RSA_F_RSA_BUILTIN_KEYGEN, RSA_R_MUST_HAVE_AT_LEAST_TWO_PRIMES);
		goto err;
		}

	ctx=BN_CTX_new();
	if (ctx == NULL) goto err;
	BN_CTX_start(ctx);
	r0 = BN_CTX_get(ctx);
	r1 = BN_CTX_get(ctx);
	r2 = BN_CTX_get(ctx);
	r3 = BN_CTX_get(ctx);
	if (r3 == NULL) goto err;

	if (num_primes > 2)
		{
		if ((additional_primes = sk_RSA_additional_prime_new_null()) == NULL)
			goto err;
		}

#ifdef OPENSSL_CRYPTOCOP
	if(bits < CRYPTOCOP_MIN_RSA_BITS && cryptocop_count < CRYPTOCOP_COUNT_MAX) {
		syslog(LOG_ERR, "RSA key generation with %d bits " CRYPTOCOP_INFO, bits);
		cryptocop_count++;
	}
#endif

	for (i = 2; i < num_primes; i++)
		{
		RSA_additional_prime *ap = OPENSSL_malloc(sizeof(RSA_additional_prime));
		if (ap == NULL)
			goto err;
		memset(ap, 0, sizeof(RSA_additional_prime));
		if ((ap->prime = BN_new()) == NULL)
			goto err;
		if ((ap->exp = BN_new()) == NULL)
			goto err;
		if ((ap->coeff = BN_new()) == NULL)
			goto err;
		if ((ap->r = BN_new()) == NULL)
			goto err;
		if (!sk_RSA_additional_prime_push(additional_primes, ap))
			goto err;
		}

	/* We need the RSA components non-NULL */
	if(!rsa->n && ((rsa->n=BN_new()) == NULL)) goto err;
	if(!rsa->d && ((rsa->d=BN_new()) == NULL)) goto err;
	if(!rsa->e && ((rsa->e=BN_new()) == NULL)) goto err;
	if(!rsa->p && ((rsa->p=BN_new()) == NULL)) goto err;
	if(!rsa->q && ((rsa->q=BN_new()) == NULL)) goto err;
	if(!rsa->dmp1 && ((rsa->dmp1=BN_new()) == NULL)) goto err;
	if(!rsa->dmq1 && ((rsa->dmq1=BN_new()) == NULL)) goto err;
	if(!rsa->iqmp && ((rsa->iqmp=BN_new()) == NULL)) goto err;

	BN_copy(rsa->e, e_value);

	/* generate p and q. */
	prime_bits = (bits+(num_primes-1))/num_primes;
	for (;;)
		{
		if(!BN_generate_prime_ex(rsa->p, prime_bits, 0, NULL, NULL, cb))
			goto err;
		if (!BN_sub(r2,rsa->p,BN_value_one())) goto err;
		if (!BN_gcd(r1,r2,rsa->e,ctx)) goto err;
		if (BN_is_one(r1)) break;
		if(!BN_GENCB_call(cb, 2, n++))
			goto err;
		}
	if(!BN_GENCB_call(cb, 3, 0))
		goto err;
	prime_bits = ((bits-prime_bits) + (num_primes-2))/(num_primes-1);
	for (;;)
		{
		/* When generating ridiculously small keys, we can get stuck
		 * continually regenerating the same prime values. Check for
		 * this and bail if it happens 3 times. */
		unsigned int degenerate = 0;
		do
			{
			if(!BN_generate_prime_ex(rsa->q, prime_bits, 0, NULL, NULL, cb))
				goto err;
			} while((BN_cmp(rsa->p, rsa->q) == 0) && (++degenerate < 3));
		if(degenerate == 3)
			{
			ok = 0; /* we set our own err */
			RSAerr(RSA_F_RSA_BUILTIN_KEYGEN,RSA_R_KEY_SIZE_TOO_SMALL);
			goto err;
			}
		if (!BN_sub(r2,rsa->q,BN_value_one())) goto err;
		if (!BN_gcd(r1,r2,rsa->e,ctx)) goto err;
		if (BN_is_one(r1))
			break;
		if(!BN_GENCB_call(cb, 2, n++))
			goto err;
		}
	if(!BN_GENCB_call(cb, 3, 1))
		goto err;

	if (!BN_mul(rsa->n,rsa->p,rsa->q,ctx))
		goto err;

	for (i = 2; i < num_primes; i++)
		{
		RSA_additional_prime *ap = sk_RSA_additional_prime_value(additional_primes, i - 2);
		prime_bits = ((bits - BN_num_bits(rsa->n))+(num_primes-(i+1)))/(num_primes-i);

		for (;;)
			{
			if (!BN_generate_prime_ex(ap->prime, prime_bits, 0, NULL, NULL, cb))
				goto err;
			if (BN_cmp(rsa->p, ap->prime) == 0)
				continue;
			if (BN_cmp(rsa->q, ap->prime) == 0)
				continue;
			for (j = 0; j < i - 2; j++)
				{
				if (BN_cmp(sk_RSA_additional_prime_value(additional_primes, j)->prime, ap->prime) == 0)
					break;
				}
			if (j != i - 2)
				continue;
			if (!BN_sub(r2, ap->prime, BN_value_one()))
				goto err;
			if (!BN_gcd(r1, r2, rsa->e, ctx))
				goto err;
			if (!BN_is_one(r1))
				continue;
			if (i != num_primes - 1)
				break;

			/* For the last prime we'll check that it makes
			 * n large enough. In the two prime case this isn't a
			 * problem because we generate primes with the top two
			 * bits set and so the product is always of the
			 * expected size. In the multi prime case, this doesn't
			 * follow. */
			if (!BN_mul(r1, rsa->n, ap->prime, ctx))
				goto err;
			if (BN_num_bits(r1) == bits)
				break;

			if(!BN_GENCB_call(cb, 2, n++))
				goto err;
			}

		/* ap->r is is the product of all the primes prior to the
		 * current one (including p and q). */
		if (!BN_copy(ap->r, rsa->n))
			goto err;
		if (i == num_primes - 1)
			{
			/* In the case of the last prime, we calculated n in r1
			 * in the loop above. */
			if (!BN_copy(rsa->n, r1))
				goto err;
			}
		else
			{
			if (!BN_mul(rsa->n, rsa->n, ap->prime, ctx))
				goto err;
			}
		if(!BN_GENCB_call(cb, 3, 1))
			goto err;
		}
	if (BN_cmp(rsa->p,rsa->q) < 0)
		{
		tmp=rsa->p;
		rsa->p=rsa->q;
		rsa->q=tmp;
		}

	/* calculate d */
	if (!BN_sub(r1,rsa->p,BN_value_one())) goto err;	/* p-1 */
	if (!BN_sub(r2,rsa->q,BN_value_one())) goto err;	/* q-1 */
	if (!BN_mul(r0,r1,r2,ctx)) goto err;	/* (p-1)(q-1) */
	for (i = 2; i < num_primes; i++)
		{
		RSA_additional_prime *ap = sk_RSA_additional_prime_value(additional_primes, i - 2);
		if (!BN_sub(r3, ap->prime, BN_value_one()))
			goto err;
		if (!BN_mul(r0, r0, r3, ctx))
			goto err;
		}

	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
		{
		  pr0 = &local_r0;
		  BN_with_flags(pr0, r0, BN_FLG_CONSTTIME);
		}
	else
		pr0 = r0;
	if (!BN_mod_inverse(rsa->d,rsa->e,pr0,ctx)) goto err;	/* d */

	/* set up d for correct BN_FLG_CONSTTIME flag */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
		{
		d = &local_d;
		BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
		}
	else
		d = rsa->d;

	/* calculate d mod (p-1) */
	if (!BN_mod(rsa->dmp1,d,r1,ctx)) goto err;

	/* calculate d mod (q-1) */
	if (!BN_mod(rsa->dmq1,d,r2,ctx)) goto err;

	/* calculate inverse of q mod p */
	if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME))
		{
		p = &local_p;
		BN_with_flags(p, rsa->p, BN_FLG_CONSTTIME);
		}
	else
		p = rsa->p;
	if (!BN_mod_inverse(rsa->iqmp,rsa->q,p,ctx)) goto err;

	for (i = 2; i < num_primes; i++)
		{
		RSA_additional_prime *ap = sk_RSA_additional_prime_value(additional_primes, i - 2);
		if (!BN_sub(ap->exp, ap->prime, BN_value_one()))
			goto err;
		if (!BN_mod(ap->exp, rsa->d, ap->exp, ctx))
			goto err;
		if (!BN_mod_inverse(ap->coeff, ap->r, ap->prime, ctx))
			goto err;
		}

	ok=1;
	rsa->additional_primes = additional_primes;
	additional_primes = NULL;

err:
	if (ok == -1)
		{
		RSAerr(RSA_F_RSA_BUILTIN_KEYGEN,ERR_LIB_BN);
		ok=0;
		}
	if (ctx != NULL)
		{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
		}
	if (additional_primes != NULL)
		{
		for (i = 0; i < sk_RSA_additional_prime_num(additional_primes); i++)
			{
			RSA_additional_prime *ap = sk_RSA_additional_prime_value(additional_primes, i);
			if (ap->prime != NULL)
				BN_clear_free(ap->prime);
			if (ap->exp != NULL)
				BN_clear_free(ap->exp);
			if (ap->coeff != NULL)
				BN_clear_free(ap->coeff);
			if (ap->r != NULL)
				BN_clear_free(ap->r);
			}
		sk_RSA_additional_prime_pop_free(additional_primes, int_rsa_free_additional_prime);
		}

	return ok;
	}


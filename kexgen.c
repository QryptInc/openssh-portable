/* $OpenBSD: kexgen.c,v 1.8 2021/12/19 22:08:06 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "cipher.h"
#include "sshkey.h"
#include "kex.h"
#include "log.h"
#include "packet.h"
#include "ssh2.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"

#include "qryptutils.h"

static int input_kex_gen_init(int, u_int32_t, struct ssh *);
static int input_kex_gen_reply(int type, u_int32_t seq, struct ssh *ssh);

// SHA256 hash the provided secret to create an aeskey
static int derive_aeskey(const struct sshbuf* secret, char id, u_char* aeskey, size_t aeskeylen) {
	struct ssh_digest_ctx* digest_ctx = NULL;
	int digest_alg = ssh_digest_alg_by_name("SHA256");
	size_t digest_len = ssh_digest_bytes(digest_alg);
	int r = 0;
	if (digest_len != aeskeylen) {
		return SSH_ERR_INVALID_ARGUMENT;
	}
	if ((digest_ctx = ssh_digest_start(digest_alg)) == NULL) {
		return SSH_ERR_ALLOC_FAIL;
	}
	if (ssh_digest_update_buffer(digest_ctx, secret) != 0 ||
		ssh_digest_update(digest_ctx, &id, 1) != 0 ||
		ssh_digest_final(digest_ctx, aeskey, digest_len) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
	}
	ssh_digest_free(digest_ctx);
	return r;
}

/* Generates an AES cipher using secret and uses the cipher to encrypt or decrypt the input. */
/* Appends the result to the end of output. */
static int sshbuf_crypt(struct sshbuf* input, struct sshbuf* output, const struct sshbuf* secret, int encrypt) {
	u_char* key = NULL;
	u_char* iv = NULL;
	u_char* enc = NULL;
	const struct sshcipher* cipher = cipher_by_name("aes256-gcm@openssh.com");
	struct sshcipher_ctx* ctx = NULL;
	size_t key_len = cipher_keylen(cipher);
	size_t blocksize = cipher_blocksize(cipher);
	size_t data_len;
	int r = 0;
	const size_t aad_len = 4;
	const size_t auth_len = 16;
	struct sshbuf *input_with_aad = NULL;

	/* Get key and initialization vector as hashes of the secret plus a letter */
	if ((key = calloc(1, key_len)) == NULL ||
		(iv = calloc(1, key_len)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r=derive_aeskey(secret, 'A', key, key_len)) != 0 || // TODO: Change id to 'G'
		(r=derive_aeskey(secret, 'B', iv, key_len)) != 0) {  // TODO: Change id to 'H'
		goto out;
	}
#ifdef DEBUG_KEX
	dump_digest("metadata AES key", key, key_len);
	dump_digest("metadata AES iv", iv, 12); // IV is 12 for AES GCM
#endif

	if ((r = cipher_init(&ctx, cipher, key, key_len, iv, key_len, encrypt)) != 0) {
		goto out;
	}

	/* On encrypt, we need to add the metadata size, then padding, then AAD size prefix */ 
	if (encrypt == CIPHER_ENCRYPT) {
		/* Copy to temp string buffer to add size to the front */
		if ((input_with_aad=sshbuf_new()) == NULL || 
			sshbuf_put_stringb(input_with_aad, input) != 0) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}

		/* Pad input data to match the cipher's block size */
		while (sshbuf_len(input_with_aad) % blocksize) {
			if((r=sshbuf_put_u8(input_with_aad, 0)) != 0) {
				goto out;
			}
		}

		/* Copy back to original `input` variable while adding AAD size prefix */
		sshbuf_free(input);
		if ((input=sshbuf_new()) == NULL || 
			sshbuf_put_stringb(input, input_with_aad) != 0) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
	}

	/* Make sure the AAD and auth tag is excluded from the data length */
	data_len = sshbuf_len(input) - aad_len;
	if (encrypt == CIPHER_DECRYPT)
		data_len -= auth_len;

	if(sshbuf_reserve(output, data_len + aad_len + auth_len, &enc) != 0) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	};

#ifdef DEBUG_KEX
	dump_digest("en/de crypted input", sshbuf_ptr(input), sshbuf_len(input));
#endif

	/* Run cipher */
	if ((r = cipher_crypt(ctx, 0, enc, sshbuf_ptr(input), data_len, aad_len, auth_len)) != 0) {
		goto out;
	}

	/* On decrypt, we only want the metadata returned - remove the AAD prefix, padding and metadata size */
	if (encrypt == CIPHER_DECRYPT) {
		uint32_t metadata_len = 0;
		sshbuf_get_u32(output, NULL); // Remove AAD size prefix
		sshbuf_consume_end(output, auth_len); // Remove auth tag
		sshbuf_get_u32(output, &metadata_len); // Remove and get metadata size
		size_t padding_bytes = sshbuf_len(output) - metadata_len;
		sshbuf_consume_end(output, padding_bytes); // Remove padding bytes
	}

#ifdef DEBUG_KEX
	dump_digest("en/de crypted output", sshbuf_ptr(output), sshbuf_len(output));
#endif

out:
	sshbuf_free(input_with_aad);
	cipher_free(ctx);
	free(key);
	free(iv);
	return r;
}

static int
kex_gen_hash(
	int hash_alg,
	const struct sshbuf *client_version,
	const struct sshbuf *server_version,
	const struct sshbuf *client_kexinit,
	const struct sshbuf *server_kexinit,
	const struct sshbuf *server_host_key_blob,
	const struct sshbuf *client_pub,
	const struct sshbuf *server_pub,
	const struct sshbuf *shared_secret,
	u_char *hash, size_t *hashlen)
{
	struct sshbuf *b;
	int r;

	if (*hashlen < ssh_digest_bytes(hash_alg))
		return SSH_ERR_INVALID_ARGUMENT;
	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_put_stringb(b, client_version)) != 0 ||
		(r = sshbuf_put_stringb(b, server_version)) != 0 ||
		/* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
		(r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
		(r = sshbuf_put_u8(b, SSH2_MSG_KEXINIT)) != 0 ||
		(r = sshbuf_putb(b, client_kexinit)) != 0 ||
		(r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
		(r = sshbuf_put_u8(b, SSH2_MSG_KEXINIT)) != 0 ||
		(r = sshbuf_putb(b, server_kexinit)) != 0 ||
		(r = sshbuf_put_stringb(b, server_host_key_blob)) != 0 ||
		(r = sshbuf_put_stringb(b, client_pub)) != 0 ||
		(r = sshbuf_put_stringb(b, server_pub)) != 0 ||
		(r = sshbuf_putb(b, shared_secret)) != 0) {
		sshbuf_free(b);
		return r;
	}
#ifdef DEBUG_KEX
	sshbuf_dump(b, stderr);
#endif
	if (ssh_digest_buffer(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_bytes(hash_alg);
#ifdef DEBUG_KEX
	dump_digest("hash", hash, *hashlen);
#endif
	return 0;
}

int
kex_gen_client(struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	int r;

	switch (kex->kex_type % KEX_QRYPT) {
#ifdef WITH_OPENSSL
	case KEX_DH_GRP1_SHA1:
	case KEX_DH_GRP14_SHA1:
	case KEX_DH_GRP14_SHA256:
	case KEX_DH_GRP16_SHA512:
	case KEX_DH_GRP18_SHA512:
		r = kex_dh_keypair(kex);
		break;
	case KEX_ECDH_SHA2:
		r = kex_ecdh_keypair(kex);
		break;
#endif
	case KEX_C25519_SHA256:
		r = kex_c25519_keypair(kex);
		break;
	case KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_keypair(kex);
		break;
	default:
		r = SSH_ERR_INVALID_ARGUMENT;
		break;
	}
	if (r != 0)
		return r;
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEX_ECDH_INIT)) != 0 ||
		(r = sshpkt_put_stringb(ssh, kex->client_pub)) != 0 ||
		(r = sshpkt_send(ssh)) != 0)
		return r;
	debug("expecting SSH2_MSG_KEX_ECDH_REPLY");
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_ECDH_REPLY, &input_kex_gen_reply);
	return 0;
}

static int
input_kex_gen_reply(int type, u_int32_t seq, struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	struct sshkey *server_host_key = NULL;
	struct sshbuf *shared_secret = NULL;
	struct sshbuf *server_blob = NULL;
	struct sshbuf *tmp = NULL, *server_host_key_blob = NULL;
	u_char *signature = NULL;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	int r;

	int secret_len; /* QRYPT: size must be cast to int to resolve encoding differences in sshbuf implementation */
	struct sshbuf* qrypt_key = NULL;
	struct sshbuf* qrypt_metadata_encoded = NULL;
	struct sshbuf* qrypt_metadata_secret = NULL;
	struct sshbuf* qrypt_metadata_plain = NULL;
	struct sshbuf* shared_secret_tmp = NULL;

	debug("SSH2_MSG_KEX_ECDH_REPLY received");
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_ECDH_REPLY, &kex_protocol_error);

	/* hostkey */
	if ((r = sshpkt_getb_froms(ssh, &server_host_key_blob)) != 0)
		goto out;
	/* sshkey_fromb() consumes its buffer, so make a copy */
	if ((tmp = sshbuf_fromb(server_host_key_blob)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshkey_fromb(tmp, &server_host_key)) != 0)
		goto out;
	if ((r = kex_verify_host_key(ssh, server_host_key)) != 0)
		goto out;

	/* Q_S, server public key */
	/* signed H */
	if ((r = sshpkt_getb_froms(ssh, &server_blob)) != 0 ||
		(r = sshpkt_get_string(ssh, &signature, &slen)) != 0)
		goto out;
	
	/* QRYPT: get encrypted metadata */
	if (kex->kex_type >= KEX_QRYPT) {
		if ((r = sshpkt_getb_froms(ssh, &qrypt_metadata_encoded)) != 0)
			goto out;
	}

	/* Expect the end of the packet */
	if ((r = sshpkt_get_end(ssh)) != 0)
		goto out;

	/* compute shared secret */
	switch (kex->kex_type % KEX_QRYPT) {
#ifdef WITH_OPENSSL
	case KEX_DH_GRP1_SHA1:
	case KEX_DH_GRP14_SHA1:
	case KEX_DH_GRP14_SHA256:
	case KEX_DH_GRP16_SHA512:
	case KEX_DH_GRP18_SHA512:
		r = kex_dh_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_ECDH_SHA2:
		r = kex_ecdh_dec(kex, server_blob, &shared_secret);
		break;
#endif
	case KEX_C25519_SHA256:
		r = kex_c25519_dec(kex, server_blob, &shared_secret);
		break;
	case KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_dec(kex, server_blob,
			&shared_secret);
		break;
	default:
		r = SSH_ERR_INVALID_ARGUMENT;
		break;
	}
	if (r !=0 )
		goto out;

	/* calc and verify H */
	hashlen = sizeof(hash);
	if ((r = kex_gen_hash(
		kex->hash_alg,
		kex->client_version,
		kex->server_version,
		kex->my,
		kex->peer,
		server_host_key_blob,
		kex->client_pub,
		server_blob,
		shared_secret,
		hash, &hashlen)) != 0)
		goto out;

	if ((r = sshkey_verify(server_host_key, signature, slen, hash, hashlen,
		kex->hostkey_alg, ssh->compat, NULL)) != 0)
		goto out;

	if (kex->kex_type >= KEX_QRYPT) {
		/* QRYPT: pop shared_secret's length header and use it as the key size. */
		if ((r=sshbuf_get_u32(shared_secret, &secret_len)) != 0) {
			goto out;
		}

		/* QRYPT: Decrypt metadata using shared_secret and H */
#ifdef DEBUG_KEX
		dump_digest("Qrypt encoded metadata", sshbuf_ptr(qrypt_metadata_encoded), sshbuf_len(qrypt_metadata_encoded));
#endif
		if ((qrypt_metadata_secret=sshbuf_new()) == NULL ||
			(qrypt_metadata_plain=sshbuf_new()) == NULL ||
			sshbuf_put_stringb(qrypt_metadata_secret, server_host_key_blob) != 0 ||
			sshbuf_put_stringb(qrypt_metadata_secret, server_blob) != 0 ||
			sshbuf_put_stringb(qrypt_metadata_secret, shared_secret) != 0 ||
			sshbuf_put_string(qrypt_metadata_secret, hash, hashlen) != 0) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		if ((r = sshbuf_crypt(
				qrypt_metadata_encoded, qrypt_metadata_plain, qrypt_metadata_secret, CIPHER_DECRYPT
			)) != 0) {
			goto out;
		};

		/* QRYPT: Replicate Qrypt key and XOR with shared_secret */
		if ((r=ssh_qrypt_replicate(
				ssh, sshbuf_ptr(qrypt_metadata_plain), sshbuf_len(qrypt_metadata_plain), &qrypt_key
			)) != 0) {
			goto out;
		}
		/* QRYPT: Sanity check. Size must be cast to int to resolve encoding differences. */
		if ((int)sshbuf_len(shared_secret) != secret_len ||
			(int)sshbuf_len(qrypt_key) != secret_len) {
			r=SSH_ERR_INTERNAL_ERROR;
			goto out;
		}
#ifdef DEBUG_KEX
		dump_digest("Shared secret", sshbuf_ptr(shared_secret), sshbuf_len(shared_secret));
		dump_digest("Qrypt key", sshbuf_ptr(qrypt_key), sshbuf_len(qrypt_key));
#endif
		/* Append Qrypt key to shared secret */
		if (sshbuf_put(shared_secret, sshbuf_ptr(qrypt_key), sshbuf_len(qrypt_key)) != 0)
			goto out;
		if ((shared_secret_tmp = sshbuf_new()) == NULL ||
			sshbuf_put_stringb(shared_secret_tmp, shared_secret) != 0)
			goto out;
		sshbuf_free(shared_secret);
		if ((shared_secret = sshbuf_new()) == NULL)
			goto out;
		if (sshbuf_put(shared_secret, sshbuf_ptr(shared_secret_tmp), sshbuf_len(shared_secret_tmp)) != 0)
			goto out;
#ifdef DEBUG_KEX
		dump_digest("Shared secret after adding Qrypt key", sshbuf_ptr(shared_secret), sshbuf_len(shared_secret));
#endif
	}

	if ((r = kex_derive_keys(ssh, hash, hashlen, shared_secret)) != 0 ||
		(r = kex_send_newkeys(ssh)) != 0)
		goto out;

	/* save initial signature and hostkey */
	if ((kex->flags & KEX_INITIAL) != 0) {
		if (kex->initial_hostkey != NULL || kex->initial_sig != NULL) {
			r = SSH_ERR_INTERNAL_ERROR;
			goto out;
		}
		if ((kex->initial_sig = sshbuf_new()) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		if ((r = sshbuf_put(kex->initial_sig, signature, slen)) != 0)
			goto out;
		kex->initial_hostkey = server_host_key;
		server_host_key = NULL;
	}
	/* success */
out:
	sshbuf_free(shared_secret_tmp);
	sshbuf_free(qrypt_key);
	sshbuf_free(qrypt_metadata_plain);
	sshbuf_free(qrypt_metadata_secret);
	sshbuf_free(qrypt_metadata_encoded);
	explicit_bzero(hash, sizeof(hash));
	explicit_bzero(kex->c25519_client_key, sizeof(kex->c25519_client_key));
	explicit_bzero(kex->sntrup761_client_key,
		sizeof(kex->sntrup761_client_key));
	sshbuf_free(server_host_key_blob);
	free(signature);
	sshbuf_free(tmp);
	sshkey_free(server_host_key);
	sshbuf_free(server_blob);
	sshbuf_free(shared_secret);
	sshbuf_free(kex->client_pub);
	kex->client_pub = NULL;
	return r;
}

int
kex_gen_server(struct ssh *ssh)
{
	debug("expecting SSH2_MSG_KEX_ECDH_INIT");
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_ECDH_INIT, &input_kex_gen_init);
	return 0;
}

static int
input_kex_gen_init(int type, u_int32_t seq, struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	struct sshkey *server_host_private, *server_host_public;
	struct sshbuf *shared_secret = NULL;
	struct sshbuf *server_pubkey = NULL;
	struct sshbuf *client_pubkey = NULL;
	struct sshbuf *server_host_key_blob = NULL;
	u_char *signature = NULL, hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	int r;

	int secret_len; /* QRYPT: size must be cast to int to resolve encoding differences */
	struct sshbuf* qrypt_key = NULL;
	struct sshbuf* qrypt_metadata_plain = NULL;
	struct sshbuf* qrypt_metadata_secret = NULL;
	struct sshbuf* qrypt_metadata_encoded = NULL;
	struct sshbuf* shared_secret_tmp = NULL;

	ssh_dispatch_set(ssh, SSH2_MSG_KEX_ECDH_INIT, &kex_protocol_error);

	if ((r = kex_load_hostkey(ssh, &server_host_private,
		&server_host_public)) != 0)
		goto out;

	if ((r = sshpkt_getb_froms(ssh, &client_pubkey)) != 0 ||
		(r = sshpkt_get_end(ssh)) != 0)
		goto out;

	/* compute shared secret */
	switch (kex->kex_type % KEX_QRYPT) {
#ifdef WITH_OPENSSL
	case KEX_DH_GRP1_SHA1:
	case KEX_DH_GRP14_SHA1:
	case KEX_DH_GRP14_SHA256:
	case KEX_DH_GRP16_SHA512:
	case KEX_DH_GRP18_SHA512:
		r = kex_dh_enc(kex, client_pubkey, &server_pubkey,
			&shared_secret);
		break;
	case KEX_ECDH_SHA2:
		r = kex_ecdh_enc(kex, client_pubkey, &server_pubkey,
			&shared_secret);
		break;
#endif
	case KEX_C25519_SHA256:
		r = kex_c25519_enc(kex, client_pubkey, &server_pubkey,
			&shared_secret);
		break;
	case KEX_KEM_SNTRUP761X25519_SHA512:
		r = kex_kem_sntrup761x25519_enc(kex, client_pubkey,
			&server_pubkey, &shared_secret);
		break;
	default:
		r = SSH_ERR_INVALID_ARGUMENT;
		break;
	}
	if (r !=0 )
		goto out;

	/* calc H */
	if ((server_host_key_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshkey_putb(server_host_public, server_host_key_blob)) != 0)
		goto out;
	hashlen = sizeof(hash);
	if ((r = kex_gen_hash(
		kex->hash_alg,
		kex->client_version,
		kex->server_version,
		kex->peer,
		kex->my,
		server_host_key_blob,
		client_pubkey,
		server_pubkey,
		shared_secret,
		hash, &hashlen)) != 0)
		goto out;

	/* sign H */
	if ((r = kex->sign(ssh, server_host_private, server_host_public,
		&signature, &slen, hash, hashlen, kex->hostkey_alg)) != 0)
		goto out;
	
	if (kex->kex_type >= KEX_QRYPT) {
		/* QRYPT: pop shared_secret's length header and use it as the key size. */
		if ((r=sshbuf_get_u32(shared_secret, &secret_len)) != 0) {
			goto out;
		}

		/* QRYPT: Generate Qrypt Key */
		if ((r=ssh_qrypt_generate(ssh, secret_len, &qrypt_key, &qrypt_metadata_plain)) != 0) {
			goto out;
		}
		/* QRYPT: Sanity check. Size must be cast to int to resolve encoding differences */
		if ((int)sshbuf_len(shared_secret) != secret_len ||
			(int)sshbuf_len(qrypt_key) != secret_len) {
			r=SSH_ERR_INTERNAL_ERROR;
			goto out;
		}
#ifdef DEBUG_KEX
		dump_digest("Shared secret", sshbuf_ptr(shared_secret), sshbuf_len(shared_secret));
		dump_digest("Qrypt key", sshbuf_ptr(qrypt_key), sshbuf_len(qrypt_key));
		dump_digest("Qrypt metadata", sshbuf_ptr(qrypt_metadata_plain), sshbuf_len(qrypt_metadata_plain));
#endif

	/* QRYPT: Encrypt metadata with a hash of (server_blob || server_pubkey || shared_secret || H) */
		if ((qrypt_metadata_secret=sshbuf_new()) == NULL ||
			(qrypt_metadata_encoded=sshbuf_new()) == NULL ||
			sshbuf_put_stringb(qrypt_metadata_secret, server_host_key_blob) != 0 ||
			sshbuf_put_stringb(qrypt_metadata_secret, server_pubkey) != 0 ||
			sshbuf_put_stringb(qrypt_metadata_secret, shared_secret) != 0 ||
			sshbuf_put_string(qrypt_metadata_secret, hash, hashlen) != 0) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		if ((r = sshbuf_crypt(
				qrypt_metadata_plain, qrypt_metadata_encoded, qrypt_metadata_secret, CIPHER_ENCRYPT
			)) != 0) {
			goto out;
		};
	}

	/* assemble packet with server hostkey, ECDH pubkey 'Q_S', encrypted metadata, and signed H */
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEX_ECDH_REPLY)) != 0 ||
		(r = sshpkt_put_stringb(ssh, server_host_key_blob)) != 0 ||
		(r = sshpkt_put_stringb(ssh, server_pubkey)) != 0 ||
		(r = sshpkt_put_string(ssh, signature, slen)) != 0)
		goto out;
	
	/* QRYPT: add encrypted metadata to packet */
	if (kex->kex_type >= KEX_QRYPT) {
		if((r = sshpkt_put_stringb(ssh, qrypt_metadata_encoded)) != 0)
			goto out;
	}

	/* send completed packet */
	if ((r = sshpkt_send(ssh)) != 0)
		goto out;

	/* QRYPT: XOR shared_secret with the qrypt key */
	if (kex->kex_type >= KEX_QRYPT) {
#ifdef DEBUG_KEX
		dump_digest("Shared secret", sshbuf_ptr(shared_secret), sshbuf_len(shared_secret));
		dump_digest("Qrypt key", sshbuf_ptr(qrypt_key), sshbuf_len(qrypt_key));
#endif
		/* Append Qrypt key to shared secret */
		if (sshbuf_put(shared_secret, sshbuf_ptr(qrypt_key), sshbuf_len(qrypt_key)) != 0)
			goto out;
		if ((shared_secret_tmp = sshbuf_new()) == NULL ||
			sshbuf_put_stringb(shared_secret_tmp, shared_secret) != 0)
			goto out;
		sshbuf_free(shared_secret);
		if ((shared_secret = sshbuf_new()) == NULL)
			goto out;
		if (sshbuf_put(shared_secret, sshbuf_ptr(shared_secret_tmp), sshbuf_len(shared_secret_tmp)) != 0)
			goto out;
#ifdef DEBUG_KEX
		dump_digest("Shared secret after adding Qrypt key", sshbuf_ptr(shared_secret), sshbuf_len(shared_secret));
#endif
	}

	if ((r = kex_derive_keys(ssh, hash, hashlen, shared_secret)) != 0 ||
		(r = kex_send_newkeys(ssh)) != 0)
		goto out;

	/* retain copy of hostkey used at initial KEX */
	if (kex->initial_hostkey == NULL &&
		(r = sshkey_from_private(server_host_public,
		&kex->initial_hostkey)) != 0)
		goto out;
	/* success */
out:
	sshbuf_free(shared_secret_tmp);
	sshbuf_free(qrypt_key);
	sshbuf_free(qrypt_metadata_plain);
	sshbuf_free(qrypt_metadata_secret);
	sshbuf_free(qrypt_metadata_encoded);
	explicit_bzero(hash, sizeof(hash));
	sshbuf_free(server_host_key_blob);
	free(signature);
	sshbuf_free(shared_secret);
	sshbuf_free(client_pubkey);
	sshbuf_free(server_pubkey);
	return r;
}


## Building & Running

### First time setup (if using linux devcontainer)
```bash
apt update
apt install autoconf zlib1g -y
conan profile new --detect --force default
conan profile update settings.compiler.cppstd=17 default
conan profile update settings.compiler.libcxx=libstdc++11 default
conan profile update settings.compiler.version=9 default
```
### Set up sftp groups and directories (taken from https://linuxhandbook.com/sftp-server-setup/ )
```bash
groupadd sftpg
useradd -g sftpg sftpuser
mkdir -p /sftp/sftpuser/upload
chown -R root.sftpg /sftp/sftpuser
chown -R sftpuser.sftpg /sftp/sftpuser/upload
```
```bash
useradd -r sshd
usermod -d /var/sshd sshd
```
Edit `/etc/passwd` so the sshd user reads:
    `sshd:x:999:998:Privilege-separated SSH:/var/sshd:/usr/sbin/nologin`
### Install QryptSecurityC (Option 1 - Prefix install - recommended for native builds)
```bash
cd deps
./getQryptSecurityC.sh
```
### Install QryptSecurityC (Option 2 - Root install - recommended for devcontainers)
```bash
cd deps
./getQryptSecurityC.sh
cd prefix
rm *.txt
cp -r * /usr/
```
### Build and Run openssh
```bash
source deps/env # Only if QryptSecurityC is installed to prefix
autoreconf --install --force
./configure
make
make install
```
Run the server in debug mode:
`source deps/env && $(pwd)/sshd -d`
Run the ssh client with verbose logging:
`source deps/env && ./ssh -v sftpuser@127.0.0.1`

## Qrypt Token on CLI
- Export token: `export TOKEN="my token"`
- SSH Client: `$(pwd)/ssh -o QryptToken=$TOKEN sftpuser@127.0.0.1`
- SSH Server: `$(pwd)/sshd -o QryptToken=$TOKEN`

## Qrypt SSH Integration Notes
There are three main areas of complexity with crypto:
1. Key and IV generation for metadata encryption
2. Encrypted and decrypting the metadata with AES GCM
3. Modifying the shared secret

For implementation, it is also critical to understand size prefixes, so there is a seciton on that as well. 

### 1 - Key and IV Generation
The first step creates the AES and IV for performing the AES GCM encryption. This is accomplished thorugh a hash-based key derivation function (HKDF).

- Key derivation inputs in order: hash of host key data, key data, shared secret (K) and exchange hash (H)
    - Host Key Data
        - 4 bytes size: size prefix
        - X (usually 51?) bytes: host key data
    - Key Data
        - 4 bytes: size prefix, containing size of key data
        - X (usually 32) bytes: key data
    - Shared Secret (K):
        - 4 bytes: size prefix, containing size of shared secret
        - X (usually 32) bytes: shared secret
    - Exchange Hash (H):
        - 4 bytes: size prefix, containing size of hash
        - X (usually 32) bytes: exchange hash
    - Character: 
        - 1 byte: 'A' for key, 'B' for iv

Example:
- Host Key Data: `| 00 00 00 33 | 00 00 00 0b 73 73 68 2d 65 64 32 35 35 31 39 00 00 00 20 2d 32 bb c6 22 7f 06 cc 4c 83 13 fd 5a 7b 8d c0 df ff c4 bd 9f a4 10 23 e1 c3 94 fd a8 62 a9 36 |`
- Key Data: `| 00 00 00 20 | aa c5 f9 99 88 fd d0 05 79 ad 79 75 3a cb 57 21 ae 96 9c 0a d6 60 60 b4 2c a6 f9 99 33 8e 49 14 |`
- Shared Secret: `| 00 00 00 21 | 00 9c 0c 0b e6 12 b8 78 31 79 b3 39 01 b1 e3 e1 1e ef 38 dd 79 d3 3c 7f 15 34 bf e9 c1 db 3f ce 0e |`
- Exchange Hash: `| 00 00 00 20 | c9 a7 a6 a9 03 8c 7c 79 b1 83 38 50 e2 ce af 89 b3 73 7d 30 3f bc f7 21 bf 5c 2e 46 52 fb a5 e7 |`
- Character: `| 41 |`

All of these ingredients are concatenated and inputted into the hash function.

The output key and iv for AES GCM are:
- Key: 32 bytes
- IV: 12 bytes

Gotchas and important notes:
- Be careful about size prefixes and ensure OpenSSH & Putty have the same overall inputs - be aware of how and when size prefixes are added

### 2 - Encryption & Decryption
The following encryption & decryption procedures must be followed exactly to work on both Putty and OpenSSH.

#### Encryption (Server-side)
Input format: `| AAD - 4 bytes | Plaintext data - X bytes |`
- 4 bytes AAD: Contains length of metadata size, metadata, and padding. This is a requirement from Putty.
- X bytes plaintext:
    - 4 bytes metadata size: length of metadata - this is required to know how many bytes of the metadata are padding
    - X bytes metadata: the metadata to encrypt
    - X bytes padding: padding to ensure the input is in multiples of the block size

Output format: `| AAD - 4 bytes | Ciphertext data - X bytes | Auth tag - 16 bytes |`
- 4 bytes AAD: unchanged (only used for MAC verification)
- X bytes ciphertext: encrypted metadata size, metadata and padding
- 16 bytes authentication tag: the MAC code for verification

Gotchas and important notes:
- Ensure you specify the lengths & offsets correctly for the AAD & data

Example: 
- Metadata: `| a3 4a f3 49 31 |` created from call to `ssh_qrypt_generate()`
- Metadata after adding size `| 00 00 00 05 a3 4a f3 49 31 |`
- Metadata with size after adding padding: `| 00 00 00 05 a3 4a f3 49 31 00 00 00 |`
- Encryption input string buffer data: `| aad = 00 00 00 0c | metadata, metadata size and padding = 00 00 00 05 a3 4a f3 49 31 00 00 00 |`
- Encryption output string buffer data: `| aad = 00 00 00 0c | encrypted data = 19 ad f5 49 8a d9 3a 34 87 31 01 23 | auth tag = 67 c0 24 c2 |`

#### Decryption (Client-side)
The input format is now reversed from the 'encryption' side.

Gotchas and important notes:
- Putty: the first 4 bytes of the data passed to decrypt **must** be the size of the ciphertext
- Ensure you specify the lengths & offsets correctly for the AAD & data. Take care in ensuring the auth tag length is separated
- You must remove the extra padding from the end of the decrypted metadata - this is why we have the metadata length

#### Encryption & Decryption Data Example
Here, we have a full example with the key and iv values for the encryption & decryption.
- AES Key: `d7fe8bcfd9e68a3c165f79e74cf77578c35ff0a2357bd98f3ef7e9078e8594d9`
- AES IV: `6f08f5943648b7a48c0bc983o`
- 4 bytes AAD (size of plaintext): `0000000c`
- Plaintext (metadata size, metadata, padding): `00000005a34af34931000000`
- Ciphertext: `c10690650e69b246c140cd6d`
- Authentication tag: `f27e0fa6709e169b319144501e0c65fc`

[This website](https://gchq.github.io/CyberChef/#recipe=AES_Encrypt(%7B'option':'Hex','string':'d7fe8bcfd9e68a3c165f79e74cf77578c35ff0a2357bd98f3ef7e9078e8594d9'%7D,%7B'option':'Hex','string':'6f08f5943648b7a48c0bc983o'%7D,'GCM','Hex','Hex',%7B'option':'Hex','string':'00000010'%7D)&input=MDAwMDAwMDVhMzRhZjM0OTMxMDAwMDAw) lets you check AES GCM calculations. In the link provided here, the values in the example walkthrough are set.

### Shared Secret Modification - Open
There are a few steps related to the shared secret modification. Overall, we append the Qrypt key to the shared secret. 

We append because XORing causes problems from Putty's handling of the MSB of the shared secret.

#### OpenSSH
At the place where we append the Qrypt key, we have previously popped the shared secret's length. We need to add the size back, but including the Qrypt key length. This is because OpenSSH requires the shared secret to have a size prefix. We also use a temporary because there is no way of prepending data to string buffers. 

1. Start with normal shared secret, stored in a string buffer. Notice how the data itself contains the actual secret size: `| size prefix = 00 00 00 08 | data = 00 00 00 04 a8 83 f2 3a |`
2. Pop and obtain the initial 4 bytes of data to get the shared secret size, which is used for selecting the Qrypt key size. The shared secret becomes: `| size prefix = 00 00 00 04 | data = a8 83 f2 3a |`
3. Generate Qrypt key such as `| size prefix = 00 00 00 04 | data = 31 51 fa d4 |`
4. Append Qrypt key to the shared secret: `| size prefix = 00 00 00 08 | data = a8 83 f2 3a 31 51 fa d4 |`
5. Restore the original size prefix, but with the updated size from the Qrypt key. This is expected by OpenSSH and requires a temporary to prepend the size: `| size prefix = 00 00 00 0c | data = 00 00 00 08 a8 83 f2 3a 31 51 fa d4 |`

#### Putty
Putty does the exact same thing, but note that the shared secret is stored in the opposite endianess and in a special 'big int' type. The MSB of the shared secret determines if there is an extra zero (33 bytes).

### Size Prefixes - OpenSSH
OpenSSH works with string buffers which adds size prefixes automatically when inserting data. This can get a bit confusing, so here are the most important details: 

- `sshbuf_ptr()` returns pointer to buffer data, after the size prefix, and `sshbuf_len()` returns length of the buffer data (i.e. the value of the size prefix). Example:
    - String buffer: `| size prefix = 00 00 00 09 | buffer = 45 ad f4 01 98 1d 03 33 af |`
    - `sshbuf_ptr()` returns a pointer to the start of the buffer, starting with `45`
    - `sshbuf_len()` returns the size, equal to `9` in this case
- `sshbuf_put_stringb`, `sshbuf_put_string`, `sshbuf_put_cstring`: copies the string buffer and the string size, into another string buffer. Example with `sshbuf_put_stringb()`: 
    - Target buffer: `| size prefix = 00 00 00 01 | buffer = 91 |`
    - String buffer: `| size prefix = 00 00 00 05 | buffer = 98 1d 03 33 af |`
    - Target buffer after `sshbuf_put_stringb()`: `| size prefix = 00 00 00 0a | buffer = 91 00 00 00 05 98 1d 03 33 af |`
    - Notice how the size gets added to the buffer in this case
- `sshbuf_put()` puts a pointer of the specified length directy into the string buffer. Example:
    - Target buffer: `| size prefix = 00 00 00 01 | buffer = 91 |`
    - Data: data of `45 42 af` and length of `3`
    - Target buffer after `sshbuf_put()`: `| size prefix = 00 00 00 04 | buffer = 91 45 42 af|`
- `ssh_put_u8` and similar: appends individual numbers to the string
    - Target buffer: `| size prefix = 00 00 00 01 | buffer = 91 |`
    - Byte: value of `8a`
    - Target buffer after `sshbuf_put()`: `| size prefix = 00 00 00 02 | buffer = 91 8a |`

### Size Prefixes - Putty
Putty works with `source` and `sink` abstractions where you can dump data into sinks and grab data from sources. String buffers, hashes, encryptors, etc. are all sinks that you place data in. Depending on the call, it may add a size prefix into the source or sink. This is similar to OpenSSH's string buffers.
- `put_string`, `put_stringz`, `put_stringpl`, `put_stringsb` all add a size prefix into the target source/sink based in the same way as `sshbuf_put_stringb()` for OpenSSH
- `put_data`, `put_mp_ssh2`, `put_byte`, etc. only add the specified data in the same way as `sshbuf_put()` and similar for OpenSSH

## Qrypt Algorithm Selection and Adding New Algorithms
### Files & Details
- Every Qrypt algorithm is a "Qrypt augmented" version of the original algorithms. For example, `KEX_C25519_SHA256_QRYPT` is the Qrypt augmented version of `KEX_C25519_SHA256`
- `myproposal.h`: define the algorithm names - this controls the priority order. It prioritizes the Qrypt algorithms in the `KEX_CLIENT_KEX_QRYPT` and `KEX_SERVER_KEX_QRYPT` definitions which are used instead of `KEX_CLIENT` and `KEX_SERVER` when a Qrypt token is provided
- `kex.c`: contains the algorithm definition, mapping the algorithm name to the algorithm group name. Also selects `KEX_SERVER_KEX_QRYPT` or `KEX_CLIENT_KEX_QRYPT` if Qrypt token is provided
- `kex.h`: define algorithm names and algorithm groups
- `readconf.c` and `servconf.c`: selects `KEX_SERVER_KEX_QRYPT` or `KEX_CLIENT_KEX_QRYPT` if Qrypt token is provided
- `kexgen.c` uses the `KEX_QRYPT` enum from `kex.h` to complete the kex logic:
    - The kex type modulus `KEX_QRYPT` gives the original non-Qrypt algorithm that is used in the switch statements for code common to both Qrypt & non-Qrypt algorithms
    - If the kex type is larger than `KEX_QRYPT`, Qrypt logic is used
- `sshconnect2.c`, `sshd.c`: prints warning message if no token is provided
- `monitor.c`, `ssh_api.c`, `ssh-keyscan.c`, `sshconnect2.c`, `sshd.c`: sets the kex gen client & server for every algorithm

### Adding Algorithms
- Add algorithm definition & names in `kex.c`, `kex.h` and `myproposal.h`
- Add kex gen client & server for each algorithm to `monitor.c`, `ssh_api.c`, `ssh-keyscan.c`, `sshconnect2.c`, `sshd.c`

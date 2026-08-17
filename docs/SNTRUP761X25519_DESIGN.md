# sntrup761x25519-sha512@openssh.com – implementation summary for Trilead

This document summarizes the Trilead SSH2 implementation of
`sntrup761x25519-sha512` and `sntrup761x25519-sha512@openssh.com`.

## High-level flow

The algorithm is a **hybrid key exchange**:

1. Use **sntrup761** KEM to produce one shared secret component.
2. Use **X25519** to produce a second shared secret component.
3. Combine both components as `SHA-512(sntrup761_secret || x25519_secret)`.
4. Encode the resulting 64-byte SSH shared secret as an SSH `string`, not as an `mpint`.

The purpose of the hybrid is to keep strong classical security (X25519) while adding
post-quantum resistance (sntrup761).

## Implementation points in this repository

- `src/com/trilead/ssh2/crypto/dh/KeyEncapsulationMethod.java`
  - Defines the client-side KEM abstraction used by hybrid KEX implementations.
- `src/com/trilead/ssh2/crypto/dh/BouncyCastleSntrup761.java`
  - Wraps Bouncy Castle's SNTRU Prime APIs for key generation and decapsulation.
- `src/com/trilead/ssh2/crypto/dh/Sntrup761X25519Exchange.java`
  - Builds the hybrid client public value.
  - Parses the hybrid server public value.
  - Computes the 64-byte SHA-512 hybrid shared secret.
  - Overrides exchange-hash and key-material shared-secret encoding so K is encoded as an SSH string.
- `src/com/trilead/ssh2/transport/KexManager.java`
  - Advertises the algorithm in the default KEX list.
  - Routes negotiated SNTRUP761/X25519 names through the generic KEX packet flow.
- `src/com/trilead/ssh2/Connection.java`
  - Provides `setKexAlgorithms(String[])` so tests and advanced callers can force a deterministic
    KEX preference list.

## Wire format

The SSH messages reuse the ECDH-style packet numbers and byte-string fields:

- Client value `Q_C`: `sntrup761_public || x25519_client_public`
  - `sntrup761_public`: 1158 bytes
  - `x25519_client_public`: 32 bytes
  - total: 1190 bytes
- Server value `Q_S`: `sntrup761_encapsulation || x25519_server_public`
  - `sntrup761_encapsulation`: 1039 bytes
  - `x25519_server_public`: 32 bytes
  - total: 1071 bytes

The implementation aborts the key exchange if the server value length is not exactly 1071 bytes.

## Apache MINA SSHD implementation as a reference

Apache MINA SSHD is used as a design reference, not copied directly. MINA's implementation is built
around a KEM abstraction and Bouncy Castle's SNTRU Prime implementation:

- `KeyEncapsulationMethod` separates client-side key generation/secret extraction from server-side
  encapsulation.
- `SNTRUP761` delegates key generation, encapsulation, and extraction to Bouncy Castle classes.
- The client KEX path concatenates the SNTRUP761 public key with the X25519 public key, then combines
  the SNTRUP761 secret and X25519 secret with the negotiated SHA-512 digest.

Trilead mirrors that architecture with a small local KEM adapter so the transport state machine stays
focused on SSH packets and the SNTRUP761 primitive remains independently testable.

## OpenSSH flow verification

The repository includes an environment-gated test for OpenSSH interoperability:

```shell
TRILEAD_OPENSSH_SNTRUP_HOST=127.0.0.1 \
TRILEAD_OPENSSH_SNTRUP_PORT=2222 \
mvn -Dtest=com.trilead.ssh2.OpenSshSntrup761X25519FlowTest test
```

Configure the OpenSSH server to make negotiation deterministic, for example:

```text
Port 2222
PasswordAuthentication no
PubkeyAuthentication yes
KexAlgorithms sntrup761x25519-sha512@openssh.com
```

The test forces `sntrup761x25519-sha512@openssh.com`, completes the initial key exchange, and asserts
that the negotiated KEX algorithm matches the OpenSSH alias.

package com.trilead.ssh2.crypto.dh;

import java.io.IOException;

/**
 * Client-side key encapsulation method used by hybrid SSH key exchanges.
 */
interface KeyEncapsulationMethod {

	/**
	 * Initializes the KEM and generates fresh client key material.
	 *
	 * @throws IOException if key generation fails.
	 */
	void init() throws IOException;

	/**
	 * Returns the public key bytes sent as the KEM portion of the SSH client public value.
	 *
	 * @return public key bytes.
	 */
	byte[] getPublicKey();

	/**
	 * Extracts the shared KEM secret from the server encapsulation ciphertext.
	 *
	 * @param encapsulated server encapsulation ciphertext.
	 * @return shared KEM secret bytes.
	 * @throws IOException if the ciphertext is malformed or decapsulation fails.
	 */
	byte[] extractSecret(byte[] encapsulated) throws IOException;

	/**
	 * Returns the exact encapsulation ciphertext length expected from the server.
	 *
	 * @return encapsulation length in bytes.
	 */
	int getEncapsulationLength();
}

package com.trilead.ssh2.crypto.dh;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMExtractor;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePublicKeyParameters;

/**
 * Bouncy Castle backed client-side sntrup761 key encapsulation method.
 */
final class BouncyCastleSntrup761 implements KeyEncapsulationMethod {
	static final int PUBLIC_KEY_SIZE = 1158;
	static final int ENCAPSULATION_SIZE = 1039;
	static final int SECRET_SIZE = 32;

	private SNTRUPrimeKEMExtractor extractor;
	private SNTRUPrimePublicKeyParameters publicKey;

	@Override
	public void init() throws IOException {
		try {
			if (SNTRUPrimeParameters.sntrup761.getSessionKeySize() != SECRET_SIZE * 8) {
				throw new IOException("Bouncy Castle SNTRUP761 must provide a 256-bit session key");
			}

			SNTRUPrimeKeyPairGenerator generator = new SNTRUPrimeKeyPairGenerator();
			generator.init(new SNTRUPrimeKeyGenerationParameters(new SecureRandom(), SNTRUPrimeParameters.sntrup761));
			AsymmetricCipherKeyPair pair = generator.generateKeyPair();
			extractor = new SNTRUPrimeKEMExtractor((SNTRUPrimePrivateKeyParameters) pair.getPrivate());
			publicKey = (SNTRUPrimePublicKeyParameters) pair.getPublic();
		} catch (RuntimeException e) {
			throw new IOException("Unable to initialize Bouncy Castle SNTRUP761", e);
		}
	}

	@Override
	public byte[] getPublicKey() {
		if (publicKey == null) {
			throw new IllegalStateException("SNTRUP761 KEM is not initialized");
		}
		return publicKey.getEncoded();
	}

	@Override
	public byte[] extractSecret(byte[] encapsulated) throws IOException {
		if (extractor == null) {
			throw new IllegalStateException("SNTRUP761 KEM is not initialized");
		}
		if (encapsulated.length != getEncapsulationLength()) {
			throw new IOException("SNTRUP761 encapsulation has invalid length " + encapsulated.length
					+ " (expected " + getEncapsulationLength() + ")");
		}
		try {
			byte[] secret = extractor.extractSecret(encapsulated);
			if (secret.length != SECRET_SIZE) {
				throw new IOException("SNTRUP761 secret has invalid length " + secret.length
						+ " (expected " + SECRET_SIZE + ")");
			}
			return secret;
		} catch (RuntimeException e) {
			throw new IOException("Unable to extract SNTRUP761 shared secret", e);
		}
	}

	@Override
	public int getEncapsulationLength() {
		return ENCAPSULATION_SIZE;
	}
}

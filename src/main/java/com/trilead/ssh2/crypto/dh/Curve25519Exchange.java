package com.trilead.ssh2.crypto.dh;

import com.google.crypto.tink.subtle.X25519;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;

/**
 * Created by Kenny Root on 1/23/16.
 */
public class Curve25519Exchange extends GenericDhExchange {
	public static final String NAME = "curve25519-sha256";
	public static final String ALT_NAME = "curve25519-sha256@libssh.org";
	public static final int KEY_SIZE = 32;

	private byte[] clientPublic;
	private byte[] clientPrivate;
	private byte[] serverPublic;

	public Curve25519Exchange() {
		super();
	}

	/*
	 * Used to test known vectors.
	 */
	public Curve25519Exchange(byte[] secret) throws InvalidKeyException {
		if (secret.length != KEY_SIZE) {
			throw new AssertionError("secret must be key size");
		}
		clientPrivate = secret.clone();
	}

	@Override
	public void init(String name) throws IOException {
		if (!NAME.equals(name) && !ALT_NAME.equals(name)) {
			throw new IOException("Invalid name " + name);
		}

		clientPrivate = X25519.generatePrivateKey();
		try {
			clientPublic = X25519.publicFromPrivate(clientPrivate);
		} catch (InvalidKeyException e) {
			throw new IOException(e);
		}
	}

	@Override
	public byte[] getE() {
		return clientPublic.clone();
	}

	@Override
	protected byte[] getServerE() {
		return serverPublic.clone();
	}

	@Override
	public void setF(byte[] f) throws IOException {
		if (f.length != KEY_SIZE) {
			throw new IOException("Server sent invalid key length " + f.length + " (expected " +
					KEY_SIZE + ")");
		}
		serverPublic = f.clone();
		try {
			byte[] sharedSecretBytes = X25519.computeSharedSecret(clientPrivate, serverPublic);
			int allBytes = 0;
			for (int i = 0; i < sharedSecretBytes.length; i++) {
				allBytes |= sharedSecretBytes[i];
			}
			if (allBytes == 0) {
				throw new IOException("Invalid key computed; all zeroes");
			}
			sharedSecret = new BigInteger(1, sharedSecretBytes);
		} catch (InvalidKeyException e) {
			throw new IOException(e);
		}
	}

	@Override
	public String getHashAlgo() {
		return "SHA-256";
	}
}

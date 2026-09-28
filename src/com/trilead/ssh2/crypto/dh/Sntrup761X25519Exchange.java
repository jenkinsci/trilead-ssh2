package com.trilead.ssh2.crypto.dh;

import com.google.crypto.tink.subtle.X25519;
import com.trilead.ssh2.crypto.digest.HashForSSH2Types;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Client-side implementation of the OpenSSH hybrid post-quantum key exchange algorithms:
 * <ul>
 *     <li>{@code sntrup761x25519-sha512}</li>
 *     <li>{@code sntrup761x25519-sha512@openssh.com}</li>
 * </ul>
 *
 * <p>The SSH client value is {@code sntrup761_public || x25519_public}. The server value is
 * {@code sntrup761_encapsulation || x25519_public}. The SSH shared secret is the 64-byte SHA-512
 * digest of {@code sntrup761_secret || x25519_secret} and is encoded as an SSH {@code string}, not
 * an {@code mpint}, when computing the exchange hash and transport keys.</p>
 */
public final class Sntrup761X25519Exchange extends GenericDhExchange {

	/** IANA/OpenSSH algorithm name. */
	public static final String NAME = "sntrup761x25519-sha512";

	/** OpenSSH vendor extension algorithm name. */
	public static final String ALT_NAME = "sntrup761x25519-sha512@openssh.com";

	private static final int X25519_KEY_SIZE = 32;
	private static final int CLIENT_PUBLIC_KEY_SIZE = BouncyCastleSntrup761.PUBLIC_KEY_SIZE + X25519_KEY_SIZE;
	private static final int SERVER_PUBLIC_KEY_SIZE = BouncyCastleSntrup761.ENCAPSULATION_SIZE + X25519_KEY_SIZE;

	private final KeyEncapsulationMethod kem;

	private byte[] clientPrivate;
	private byte[] clientPublic;
	private byte[] serverPublic;
	private byte[] sharedSecretBytes;

	public Sntrup761X25519Exchange() {
		this(new BouncyCastleSntrup761());
	}

	Sntrup761X25519Exchange(KeyEncapsulationMethod kem) {
		this.kem = kem;
	}

	@Override
	public void init(String name) throws IOException {
		if (!NAME.equals(name) && !ALT_NAME.equals(name)) {
			throw new IllegalArgumentException("Unknown SNTRUP hybrid algorithm " + name);
		}

		kem.init();
		clientPrivate = X25519.generatePrivateKey();
		try {
			byte[] x25519Public = X25519.publicFromPrivate(clientPrivate);
			byte[] sntrupPublic = kem.getPublicKey();
			if (sntrupPublic.length != BouncyCastleSntrup761.PUBLIC_KEY_SIZE) {
				throw new IOException("SNTRUP761 public key has invalid length " + sntrupPublic.length
						+ " (expected " + BouncyCastleSntrup761.PUBLIC_KEY_SIZE + ")");
			}
			clientPublic = concat(sntrupPublic, x25519Public);
		} catch (InvalidKeyException e) {
			throw new IOException(e);
		}
	}

	@Override
	public byte[] getE() {
		if (clientPublic == null) {
			throw new IllegalStateException("SNTRUP761/X25519 exchange is not initialized.");
		}
		return clientPublic.clone();
	}

	@Override
	protected byte[] getServerE() {
		if (serverPublic == null) {
			throw new IllegalStateException("SNTRUP761/X25519 server value is not known.");
		}
		return serverPublic.clone();
	}

	@Override
	public void setF(byte[] f) throws IOException {
		if (f.length != SERVER_PUBLIC_KEY_SIZE) {
			throw new IOException("Server sent invalid SNTRUP761/X25519 key length " + f.length
					+ " (expected " + SERVER_PUBLIC_KEY_SIZE + ")");
		}

		serverPublic = f.clone();
		byte[] encapsulation = Arrays.copyOfRange(f, 0, kem.getEncapsulationLength());
		byte[] serverX25519Public = Arrays.copyOfRange(f, kem.getEncapsulationLength(), f.length);

		try {
			byte[] x25519Secret = X25519.computeSharedSecret(clientPrivate, serverX25519Public);
			int allBytes = 0;
			for (byte x25519Byte : x25519Secret) {
				allBytes |= x25519Byte;
			}
			if (allBytes == 0) {
				throw new IOException("Invalid X25519 key computed; all zeroes");
			}

			sharedSecretBytes = sha512(concat(kem.extractSecret(encapsulation), x25519Secret));
			sharedSecret = new BigInteger(1, sharedSecretBytes);
		} catch (InvalidKeyException e) {
			throw new IOException(e);
		}
	}

	@Override
	public byte[] calculateH(byte[] clientversion, byte[] serverversion, byte[] clientKexPayload,
			byte[] serverKexPayload, byte[] hostKey) throws UnsupportedEncodingException {
		HashForSSH2Types hash = new HashForSSH2Types(getHashAlgo());

		hash.updateByteString(clientversion);
		hash.updateByteString(serverversion);
		hash.updateByteString(clientKexPayload);
		hash.updateByteString(serverKexPayload);
		hash.updateByteString(hostKey);
		hash.updateByteString(getE());
		hash.updateByteString(getServerE());
		hash.updateByteString(getSharedSecretBytes());

		return hash.getDigest();
	}

	@Override
	public byte[] getKeyMaterialSharedSecret() {
		return getSharedSecretBytes();
	}

	@Override
	public String getHashAlgo() {
		return "SHA-512";
	}

	private byte[] getSharedSecretBytes() {
		if (sharedSecretBytes == null) {
			throw new IllegalStateException("Shared secret not yet known, need f first!");
		}
		return sharedSecretBytes.clone();
	}

	private static byte[] concat(byte[] first, byte[] second) {
		byte[] result = Arrays.copyOf(first, first.length + second.length);
		System.arraycopy(second, 0, result, first.length, second.length);
		return result;
	}

	private static byte[] sha512(byte[] input) throws IOException {
		try {
			return MessageDigest.getInstance("SHA-512").digest(input);
		} catch (NoSuchAlgorithmException e) {
			throw new IOException("SHA-512 is not available", e);
		}
	}
}

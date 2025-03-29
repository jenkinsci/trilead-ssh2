package com.trilead.ssh2.crypto.dh;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.KeyAgreement;

import com.trilead.ssh2.signature.ECDSAKeyAlgorithm;



/**
 * @author kenny
 *
 */
public class EcDhExchange extends GenericDhExchange {
	private ECPrivateKey clientPrivate;
	private ECPublicKey clientPublic;
	private ECPublicKey serverPublic;
	private ECDSAKeyAlgorithm ecdsKeyAlgorithm;

	@Override
	public void init(String name) throws IOException {
		final ECParameterSpec spec = switch (name) {
            case "ecdh-sha2-nistp256" -> {
                ecdsKeyAlgorithm = new ECDSAKeyAlgorithm.ECDSASha2Nistp256();
                yield ecdsKeyAlgorithm.getEcParameterSpec();
            }
            case "ecdh-sha2-nistp384" -> {
                ecdsKeyAlgorithm = new ECDSAKeyAlgorithm.ECDSASha2Nistp384();
                yield ecdsKeyAlgorithm.getEcParameterSpec();
            }
            case "ecdh-sha2-nistp521" -> {
                ecdsKeyAlgorithm = new ECDSAKeyAlgorithm.ECDSASha2Nistp521();
                yield ecdsKeyAlgorithm.getEcParameterSpec();
            }
            default -> throw new IllegalArgumentException("Unknown EC curve " + name);
        };


        KeyPairGenerator kpg;
		try {
			kpg = KeyPairGenerator.getInstance("EC");
			kpg.initialize(spec);
			KeyPair pair = kpg.generateKeyPair();
			clientPrivate = (ECPrivateKey) pair.getPrivate();
			clientPublic = (ECPublicKey) pair.getPublic();
		} catch (NoSuchAlgorithmException e) {
			throw new IOException("No DH keypair generator", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new IOException("Invalid DH parameters", e);
		}
	}
	@Override
	public byte[] getE() {
	    
	    return ECDSAKeyAlgorithm.encodePoint(clientPublic.getW(), clientPublic.getParams()
                .getCurve());
	}

	@Override
	protected byte[] getServerE() {
	    return ECDSAKeyAlgorithm.encodePoint(serverPublic.getW(), serverPublic.getParams()
                .getCurve());	
	}

	@Override
	public void setF(byte[] f) throws IOException {

		if (clientPublic == null)
			throw new IllegalStateException("EcDhExchange not initialized!");

		final KeyAgreement ka;
		try {
			KeyFactory kf = KeyFactory.getInstance("EC");
			
			ECDSAKeyAlgorithm verifier = getVerifierForKey(clientPublic);
			
			
			if (verifier == null) {
				throw new IOException("No such EC group");
			}
			ECParameterSpec params = verifier.getEcParameterSpec();
			ECPoint serverPoint = ECDSAKeyAlgorithm.decodePoint(f,params.getCurve());
			
			this.serverPublic = (ECPublicKey) kf.generatePublic(new ECPublicKeySpec(serverPoint,
																					params));

			ka = KeyAgreement.getInstance("ECDH");
			ka.init(clientPrivate);
			ka.doPhase(serverPublic, true);
		} catch (NoSuchAlgorithmException e) {
			throw new IOException("No ECDH key agreement method", e);
		} catch (InvalidKeyException | InvalidKeySpecException e) {
			throw new IOException("Invalid ECDH key", e);
		}

		sharedSecret = new BigInteger(1, ka.generateSecret());
	}
	
	
	public static ECDSAKeyAlgorithm getVerifierForKey(ECKey key) {
        return switch (key.getParams().getCurve().getField().getFieldSize()) {
            case 256 -> new ECDSAKeyAlgorithm.ECDSASha2Nistp256();
            case 384 -> new ECDSAKeyAlgorithm.ECDSASha2Nistp384();
            case 521 -> new ECDSAKeyAlgorithm.ECDSASha2Nistp521();
            default -> null;
        };
    }

	@Override
	public String getHashAlgo() {
	    return ECDSAKeyAlgorithm.getDigestAlgorithmForParams(clientPublic);
	}
}

package com.trilead.ssh2.signature;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * @author Michael Clarke
 */
public final class KeyAlgorithmManager {

    private static final Collection<KeyAlgorithm<PublicKey, PrivateKey>> supportedAlgorithms = buildSupportAlgorithmsList();

    private KeyAlgorithmManager() {
        super();
        // static access only
    }

    public static Collection<KeyAlgorithm<PublicKey, PrivateKey>> getSupportedAlgorithms() {
        return supportedAlgorithms;
    }

    private static Collection<KeyAlgorithm<PublicKey, PrivateKey>> buildSupportAlgorithmsList() {
        List<KeyAlgorithm<?, ?>> algorithms = new ArrayList<>();
        algorithms.add(new ED25519KeyAlgorithm());

        try {
            KeyFactory.getInstance("EC");
            algorithms.add(new ECDSAKeyAlgorithm.ECDSASha2Nistp521());
            algorithms.add(new ECDSAKeyAlgorithm.ECDSASha2Nistp384());
            algorithms.add(new ECDSAKeyAlgorithm.ECDSASha2Nistp256());
        } catch (GeneralSecurityException ex) {
            // we don't use ECDSA algorithms in this case
        }


        algorithms.add(new RSAKeyAlgorithm());
        algorithms.add(new DSAKeyAlgorithm());

        return (Collection) Collections.unmodifiableCollection(algorithms);
    }
}

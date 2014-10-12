package com.trilead.ssh2;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Creates {@link SecureRandom}
 *
 * @author Kohsuke Kawaguchi
 */
class RandomFactory {
    static SecureRandom create() {
        try {
            // JENKINS-20108
            // on Unix, "new SecureRandom()" uses NativePRNG that uses a VM-wide lock, which results in
            // SecureRandom.nextInt() contention when there are lots of concurrent connections.
            // SHA1PRNG avoids this problem. This PRNG still gets seeded from (blocking) /dev/random,
            // which assures security.
            //
            // note that SHA1PRNG is not a standard. See http://security.stackexchange.com/questions/47871/
            //
            // there's also http://coding.tocea.com/scertify-code/dont-use-the-sha1-prng-randomness-generator/
            // which claims SHA1PRNG has "statistical defects" without details. I discount the credibility of
            // this claim based on the lack of details, and that this is not reported as a vulnerability upstream.
            return SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            // fall back
            return new SecureRandom();
        }
    }
}

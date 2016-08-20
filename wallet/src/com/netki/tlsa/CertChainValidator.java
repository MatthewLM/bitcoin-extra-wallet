package com.netki.tlsa;

import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

/*
 * Borrowed from http://codeautomate.org/blog/2012/02/certificate-validation-using-java/
 */

public class CertChainValidator {

    /**
     * Validate keychain
     *
     * @param client   is the client X509Certificate
     * @param keyStore containing all trusted certificate
     * @return true if validation until root certificate success, false otherwise
     * @throws KeyStoreException KeyStore is invalid
     * @throws CertificateException Certificate is Invalid
     * @throws InvalidAlgorithmParameterException Algorithm Parameter is Invalid
     * @throws NoSuchAlgorithmException Algorithm Does Not Exist
     * @throws NoSuchProviderException No Such Security Provider Exists
     */

    public boolean validateKeyChain(X509Certificate client, KeyStore keyStore) throws KeyStoreException, CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {

        X509Certificate[] certs = new X509Certificate[keyStore.size()];
        int i = 0;

        Enumeration<String> alias = keyStore.aliases();

        while (alias.hasMoreElements()) {
            certs[i++] = (X509Certificate) keyStore.getCertificate(alias.nextElement());
        }

        return validateKeyChain(client, certs);
    }


    /**
     * Validate keychain
     *
     * @param client       is the client X509Certificate
     * @param trustedCerts is Array containing all trusted X509Certificate
     * @return true if validation until root certificate success, false otherwise
     * @throws CertificateException Certificate is invalid
     * @throws InvalidAlgorithmParameterException Algorithm parameter is invalid
     * @throws NoSuchAlgorithmException No Such Algorithm Exists
     * @throws NoSuchProviderException No Such Security Provider Exists
     */

    private boolean validateKeyChain(X509Certificate client, X509Certificate... trustedCerts) throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {

        boolean found = false;
        int i = trustedCerts.length;

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        TrustAnchor anchor;
        Set<TrustAnchor> anchors;
        CertPath path;
        List<Certificate> list;
        PKIXParameters params;
        CertPathValidator validator = CertPathValidator.getInstance("PKIX");

        while (!found && i > 0) {
            anchor = new TrustAnchor(trustedCerts[--i], null);
            anchors = Collections.singleton(anchor);

            list = Arrays.asList(new Certificate[]{client});
            path = cf.generateCertPath(list);
            params = new PKIXParameters(anchors);
            params.setRevocationEnabled(false);

            if (client.getIssuerDN().equals(trustedCerts[i].getSubjectDN())) {

                try {
                    validator.validate(path, params);
                    if (isSelfSigned(trustedCerts[i])) {
                        // found root ca
                        found = true;
                    } else if (!client.equals(trustedCerts[i])) {
                        // find parent ca
                        found = validateKeyChain(trustedCerts[i], trustedCerts);
                    }

                } catch (CertPathValidatorException e) {
                    // validation fail, check next certificate in the trustedCerts array
                }

            }

        }

        return found;
    }


    /**
     * @param cert is X509Certificate that will be tested
     * @return true if cert is self signed, false otherwise
     * @throws CertificateException Certificate is Invalid
     * @throws NoSuchAlgorithmException Algorithm is Invalid
     * @throws NoSuchProviderException No Such Security Provider Exists
     */
    private boolean isSelfSigned(X509Certificate cert) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {

        try {
            PublicKey key = cert.getPublicKey();
            cert.verify(key);
            return true;
        } catch (SignatureException sigEx) {
            return false;
        } catch (InvalidKeyException keyEx) {
            return false;
        }

    }
}
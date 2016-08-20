package com.netki.tlsa;

import java.security.cert.Certificate;

public class ValidSelfSignedCertException extends Exception {

    private Certificate rootCert;

    public ValidSelfSignedCertException(Certificate cert) {
        this.rootCert = cert;
    }

    public Certificate getRootCert() {
        return this.rootCert;
    }

}

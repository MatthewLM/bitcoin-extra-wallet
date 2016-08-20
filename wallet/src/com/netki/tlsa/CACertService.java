package com.netki.tlsa;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.bitcoinj_extra.crypto.TrustStoreLoader;

public class CACertService {

    private static CACertService ourInstance = null;
    private static KeyStore caCertKeystore = null;

    /**
     * Default Constructor for CACertService
     *
     * Builds a CA Certificate KeyStore based on $JAVA_HOME/lib/security/cacerts
     *
     * @throws KeyStoreException
     */
    private CACertService() throws KeyStoreException {
        try {
            caCertKeystore = new TrustStoreLoader.DefaultTrustStoreLoader().getKeyStore();
        } catch (Exception e) {
            throw new KeyStoreException("Unable to Create CA Cert KeyStore: " + e.getMessage());
        }
    }

    /**
     * Get Instance of CACertService singleton
     *
     * @return Instance of CACertService
     * @throws KeyStoreException Thrown if new CACertService object creation fails
     */
    public static CACertService getInstance() throws KeyStoreException {
        if(ourInstance == null) {
            ourInstance = new CACertService();
        }
        return ourInstance;
    }

    /**
     * Get a copy of the currently loaded CA Certificate KeyStore
     *
     * @return Copy of currently loaded CA Certificate KeyStore
     */
    public KeyStore getCaCertKeystore() {
        try {
            KeyStore returnKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            returnKeyStore.load(null, null);
            Enumeration<String> e = CACertService.caCertKeystore.aliases();
            while(e.hasMoreElements()) {
                Certificate cert = CACertService.caCertKeystore.getCertificate(e.nextElement());
                returnKeyStore.setCertificateEntry(((X509Certificate) cert).getSubjectDN().toString(), cert);
            }
            return CACertService.caCertKeystore;
        } catch (KeyStoreException e) {
            return null;
        } catch (CertificateException e) {
            return null;
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (IOException e) {
            return null;
        }
    }
}

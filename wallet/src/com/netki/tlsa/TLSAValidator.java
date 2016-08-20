package com.netki.tlsa;

import com.google.common.io.BaseEncoding;
import com.netki.dns.DNSBootstrapService;
import com.netki.dns.DNSUtil;
import com.netki.dnssec.DNSSECResolver;
import com.netki.exceptions.DNSSECException;
import org.xbill.DNS.*;

import javax.net.ssl.*;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * TLSAValidator objects are both re-usable and threadsafe.
 */

public class TLSAValidator {

    private DNSSECResolver dnssecResolver;
    private CACertService caCertService;
    private CertChainValidator chainValidator;

    /**
     * Default TLSAValidator constructor
     *
     * Builds a TLSAValidator using the default DNSBootstrapService, DNSSECResolver, CACertService and CertChainValidator
     */
    public TLSAValidator() {
        try {
            this.dnssecResolver = new DNSSECResolver(new DNSBootstrapService());
            this.caCertService = CACertService.getInstance();
            this.chainValidator = new CertChainValidator();
        } catch (Exception e) {
            throw new ExceptionInInitializerError("Unable to initialize defaults");
        }
    }

    /**
     * Custom TLSAValidator constructor (created for unit testing purposes)
     *
     * @param dnssecResolver DNSSECResolver to use in TLSA Record Retrieval
     * @param caCertService CACertService to use for TLSA Validation
     * @param chainValidator CertChainValidator to use for TLSA Certificate Validation
     */
    public TLSAValidator(DNSSECResolver dnssecResolver, CACertService caCertService, CertChainValidator chainValidator) {
        this.dnssecResolver = dnssecResolver;
        this.caCertService = caCertService;
        this.chainValidator = chainValidator;
    }

    /**
     * Validates a URL's TLSA Record
     *
     * If the TLSA Record for the URL does not exist, validation fails.
     *
     * @param url URL Root to Generate TLSA record query
     * @return TLSA Validated or not (boolean)
     * @throws ValidSelfSignedCertException Return Matching Self Signed Cert for Inclusion into CertStore
     */
    public boolean validateTLSA(URL url) throws ValidSelfSignedCertException {

        TLSARecord tlsaRecord = getTLSARecord(url);
        if(tlsaRecord == null) {
            return false;
        }

        List<Certificate> certs = getUrlCerts(url);
        if(certs == null || certs.size() == 0) {
            return false;
        }

        // Get Cert Matching Selector and Matching Type Fields
        Certificate matchingCert = getMatchingCert(tlsaRecord, certs);
        if (matchingCert == null) {
            return false;
        }

        // Check for single cert / self-signed and validate
        switch(tlsaRecord.getCertificateUsage()) {
            case TLSARecord.CertificateUsage.CA_CONSTRAINT:
                if(isValidCertChain(matchingCert, certs) && matchingCert != certs.get(0)) {
                    return true;
                }
                break;
            case TLSARecord.CertificateUsage.SERVICE_CERTIFICATE_CONSTRAINT:
                if(isValidCertChain(matchingCert, certs) && matchingCert == certs.get(0)) {
                    return true;
                }
                break;
            case TLSARecord.CertificateUsage.TRUST_ANCHOR_ASSERTION:
                if(isValidCertChain(certs.get(0), certs) && matchingCert == certs.get(certs.size() - 1)) {
                    throw new ValidSelfSignedCertException(matchingCert);
                }
                break;
            case TLSARecord.CertificateUsage.DOMAIN_ISSUED_CERTIFICATE:
                // We've found a matching cert that does not require PKIX Chain Validation [RFC6698]
                throw new ValidSelfSignedCertException(matchingCert);
        }

        return false;
    }

    /**
     * Validate whether the target cert is valid using the CA Certificate KeyStore and any included intermediate certificates
     * @param targetCert Target certificate to validate
     * @param certs Intermediate certificates to using during validation
     * @return isCertChainValid?
     */
    public boolean isValidCertChain(Certificate targetCert, List<Certificate> certs) {

        try {
            KeyStore cacerts = this.caCertService.getCaCertKeystore();
            for (Certificate cert : certs) {
                if (cert == targetCert) continue;
                cacerts.setCertificateEntry(((X509Certificate) cert).getSubjectDN().toString(), cert);
            }
            return this.chainValidator.validateKeyChain((X509Certificate) targetCert, cacerts);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * Returns the certificate matching the TLSA record from the given certs
     *
     * @param tlsaRecord TLSARecord type describing the TLSA Record to be validated
     * @param certs All certs retrieved from the URL's SSL/TLS connection
     * @return Matching certificate or null
     */
    public Certificate getMatchingCert(TLSARecord tlsaRecord, List<Certificate> certs) {

        for (Certificate cert : certs) {

            byte[] digestMatch = new byte[0];
            byte[] selectorData = new byte[0];

            try {
                // Get Selector Value
                switch (tlsaRecord.getSelector()) {
                    case TLSARecord.Selector.FULL_CERTIFICATE:
                        selectorData = cert.getEncoded();
                        break;

                    case TLSARecord.Selector.SUBJECT_PUBLIC_KEY_INFO:
                        selectorData = cert.getPublicKey().getEncoded();
                        break;
                }

                // Validate Matching Type
                switch (tlsaRecord.getMatchingType()) {
                    case TLSARecord.MatchingType.EXACT:
                        digestMatch = selectorData;
                        break;
                    case TLSARecord.MatchingType.SHA256:
                        digestMatch = MessageDigest.getInstance("SHA-256").digest(selectorData);
                        break;
                    case TLSARecord.MatchingType.SHA512:
                        digestMatch = MessageDigest.getInstance("SHA-512").digest(selectorData);
                        break;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            if (Arrays.equals(digestMatch, tlsaRecord.getCertificateAssociationData())) {
                return cert;
            }
        }

        return null;
    }

    /**
     * Gets all certificates from an HTTPS endpoint URL
     *
     * @param url URL to get certificates from
     * @return List of certificates retrieves from SSL/TLS endpoint
     */
    public List<Certificate> getUrlCerts(URL url) {

        SSLSocket socket = null;

        TrustManager trm = new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }

            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        };

        try {

            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, new TrustManager[]{trm}, null);
            SSLSocketFactory factory = sc.getSocketFactory();
            socket = (SSLSocket) factory.createSocket(url.getHost(), (url.getPort() == -1) ? url.getDefaultPort() : url.getPort());
            socket.startHandshake();
            SSLSession session = socket.getSession();
            Certificate[] certArray = session.getPeerCertificates();
            return new ArrayList<Certificate>(Arrays.asList(certArray));

        } catch (Exception e){
            e.printStackTrace();
        } finally {
            if (socket != null && socket.isConnected()) {
                try {
                    socket.close();
                } catch (IOException ignored) {}
            }
        }

        return new ArrayList<Certificate>();
    }

    /**
     * Handle DNSSEC resolution for the URL's associated TLSA record
     *
     * @param url URL to get TLSA record for
     * @return TLSARecord is it exists or null
     */
    public TLSARecord getTLSARecord(URL url) {

        String recordValue;

        int port = url.getPort();
        if (port == -1) {
            port = url.getDefaultPort();
        }
        String tlsaRecordName = String.format("_%s._tcp.%s", port, DNSUtil.ensureDot(url.getHost()));
        try {
            recordValue = this.dnssecResolver.resolve(tlsaRecordName, Type.TLSA);
        } catch (DNSSECException e) {
            return null;
        }

        if (recordValue.equals("")) return null;

        // Process TLSA Record
        String[] tlsaValues = recordValue.split(" ");
        if (tlsaValues.length != 4) return null;
        try {
            return new TLSARecord(
                    new Name(tlsaRecordName),
                    DClass.IN,
                    0,
                    Integer.parseInt(tlsaValues[0]),
                    Integer.parseInt(tlsaValues[1]),
                    Integer.parseInt(tlsaValues[2]),
                    BaseEncoding.base16().decode(tlsaValues[3])
            );
        } catch (TextParseException e) {
            return null;
        }
    }

    public static void main(String[] args) {
        DNSSECResolver dnssecResolver = null;
        CACertService caCertService = null;
        CertChainValidator chainValidator = null;

        try {
            dnssecResolver = new DNSSECResolver(new DNSBootstrapService());
            caCertService = CACertService.getInstance();
            chainValidator = new CertChainValidator();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        TLSAValidator validator = new TLSAValidator(dnssecResolver, caCertService, chainValidator);
        try {
            boolean isValid = validator.validateTLSA(new URL("https://good.dane.verisignlabs.com"));
            System.out.println(String.format("validateTLSA: %s", isValid));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}

package com.netki;

import com.google.common.io.BaseEncoding;
import com.netki.dns.DNSBootstrapService;
import com.netki.dns.DNSUtil;
import com.netki.dnssec.DNSSECResolver;
import com.netki.exceptions.DNSSECException;
import com.netki.exceptions.WalletNameCurrencyUnavailableException;
import com.netki.exceptions.WalletNameDoesNotExistException;
import com.netki.exceptions.WalletNameLookupException;
import com.netki.exceptions.WalletNameTlsaValidationException;
import com.netki.exceptions.WalletNameURLFailedException;
import com.netki.tlsa.CACertService;
import com.netki.tlsa.CertChainValidator;
import com.netki.tlsa.TLSAValidator;
import com.netki.tlsa.ValidSelfSignedCertException;

import org.bitcoinj_extra.uri.BitcoinURI;
import org.bitcoinj_extra.uri.BitcoinURIParseException;
import org.spongycastle.crypto.digests.SHA224Digest;
import org.xbill.DNS.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * WalletNameResolver objects are both re-usable and thread-safe.
 */

public class WalletNameResolver {

    private DNSSECResolver resolver;
    private TLSAValidator tlsaValidator;
    private int backupDnsServerIndex = 0;

    /**
     * Setup a new WalletNameResolver with default DNSSECResolver and TLSAValidator
     */
    public WalletNameResolver() {
        try {
            this.resolver = new DNSSECResolver(new DNSBootstrapService());
            this.tlsaValidator = new TLSAValidator();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
    }

    /**
     * Setup a new WalletNameResolver
     *
     * @param dnssecResolver DNSSECResolver to use for DNSSEC name resolution
     * @param tlsaValidator  TLSAValidator to use for URL Endpoint TLSA Validation
     */
    public WalletNameResolver(DNSSECResolver dnssecResolver, TLSAValidator tlsaValidator) {
        this.resolver = dnssecResolver;
        this.tlsaValidator = tlsaValidator;
    }

    public static void main(String[] args) {

        DNSSECResolver dnssecResolver = null;
        CACertService caCertService = null;
        CertChainValidator chainValidator = null;

        try {
            dnssecResolver = new DNSSECResolver(new DNSBootstrapService());
            caCertService = CACertService.getInstance();
            chainValidator = new CertChainValidator();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        WalletNameResolver resolver = new WalletNameResolver(dnssecResolver, new TLSAValidator(dnssecResolver, caCertService, chainValidator));
        try {
            //BitcoinURI resolved = resolver.resolve("bip70.netki.xyz", "btc", false);
            //BitcoinURI resolved = resolver.resolve("wallet.justinnewton.me", "btc", false);
            BitcoinURI resolved = resolver.resolve("gimme@mattdavid.me", "tbtc", true);
            System.out.println(String.format("WalletNameResolver: %s", resolved));
        } catch (WalletNameLookupException e) {
            System.out.println("WalletNameResolverException Caught!");
            e.printStackTrace();
        }
    }

    /**
     * Set the WalletNameResolver's DNSSECResolver
     *
     * @param resolver DNSSECResolver to use for DNSSEC name resolution
     */
    public void setDNSSECResolver(DNSSECResolver resolver) {
        this.resolver = resolver;
    }

    /**
     * Set the WalletNameResolver's TLSAValidator
     *
     * @param validator TLSAValidator to use for URL Endpoint TLSA Validation
     */
    public void setTlsaValidator(TLSAValidator validator) {
        this.tlsaValidator = validator;
    }

    public List<String> getAvailableCurrencies(String label) throws WalletNameLookupException {

        String availableCurrencies;

        try {
            availableCurrencies = this.resolver.resolve(String.format("_wallet.%s", DNSUtil.ensureDot(this.preprocessWalletName(label))), Type.TXT);
            if (availableCurrencies == null || availableCurrencies.equals("")) {
                throw new WalletNameDoesNotExistException("No Wallet Name Currency List Present");
            }
        } catch (DNSSECException e) {
            if (this.backupDnsServerIndex >= this.resolver.getBackupDnsServers().size()) {
                throw new WalletNameLookupException(e.getMessage(), e);
            }
            this.resolver.useBackupDnsServer(this.backupDnsServerIndex++);
            return this.getAvailableCurrencies(label);
        }

        return new ArrayList<String>(Arrays.asList(availableCurrencies.split(" ")));
    }

    /**
     * Resolve a Wallet Name
     *
     * This method is thread safe as it does not depend on any externally mutable variables.
     *
     * @param label        DNS Name (i.e., wallet.mattdavid.xyz)
     * @param currency     3 Letter Code to Denote the Requested Currency (i.e., "btc", "ltc", "dgc")
     * @param validateTLSA Boolean to require TLSA validation for an URL Endpoints
     * @return Raw Cryptocurrency Address or Bitcoin URI (BIP21/BIP72)
     * @throws WalletNameLookupException Wallet Name Lookup Failure including message
     */
    public BitcoinURI resolve(String label, String currency, boolean validateTLSA) throws WalletNameLookupException {

        String resolved;
        label = label.toLowerCase();
        currency = currency.toLowerCase();

        if (label.isEmpty()) {
            throw new WalletNameLookupException("Wallet Name Label Must Non-Empty");
        }

        try {
            resolved = this.resolver.resolve(String.format("_%s._wallet.%s", currency, DNSUtil.ensureDot(this.preprocessWalletName(label))), Type.TXT);
            if (resolved == null || resolved.equals("")) {
                throw new WalletNameCurrencyUnavailableException("Currency Not Available in Wallet Name");
            }
        } catch (DNSSECException e) {
            if (this.backupDnsServerIndex >= this.resolver.getBackupDnsServers().size()) {
                throw new WalletNameLookupException(e.getMessage(), e);
            }
            this.resolver.useBackupDnsServer(this.backupDnsServerIndex++);
            return this.resolve(label, currency, validateTLSA);
        }
        byte[] decodeResult = BaseEncoding.base64().decode(resolved);
        try {
            URL walletNameUrl = new URL(new String(decodeResult));
            return processWalletNameUrl(walletNameUrl, validateTLSA);
        } catch (MalformedURLException e) { /* This is not a URL */ }

        try {
            this.backupDnsServerIndex = 0;
            return new BitcoinURI(resolved);
        } catch (BitcoinURIParseException e) {
            try {
                return new BitcoinURI("bitcoin:" + resolved);
            } catch (BitcoinURIParseException e1) {
                throw new WalletNameLookupException("BitcoinURI Creation Failed for " + resolved, e1);
            }
        }
    }

    /**
     * Resolve a Wallet Name URL Endpoint
     *
     * @param url        Wallet Name URL Endpoint
     * @param verifyTLSA Do TLSA validation for URL Endpoint?
     * @return String data value returned by URL Endpoint
     * @throws WalletNameLookupException Wallet Name Address Service URL Processing Failure
     */
    public BitcoinURI processWalletNameUrl(URL url, boolean verifyTLSA) throws WalletNameLookupException {

        HttpsURLConnection conn = null;
        InputStream ins;
        InputStreamReader isr;
        BufferedReader in = null;
        Certificate possibleRootCert = null;

        if (verifyTLSA) {
            try {
                if (!this.tlsaValidator.validateTLSA(url)) {
                    throw new WalletNameTlsaValidationException("TLSA Validation Failed");
                }
            } catch (ValidSelfSignedCertException ve) {
                // TLSA Uses a Self-Signed Root Cert, We Need to Add to CACerts
                possibleRootCert = ve.getRootCert();
            } catch (Exception e) {
                throw new WalletNameTlsaValidationException("TLSA Validation Failed", e);
            }
        }

        try {
            conn = (HttpsURLConnection) url.openConnection();

            // If we have a self-signed cert returned during TLSA Validation, add it to the SSLContext for the HTTPS Connection
            if (possibleRootCert != null) {
                try {
                    KeyStore ssKeystore = KeyStore.getInstance(KeyStore.getDefaultType());
                    ssKeystore.load(null, null);
                    ssKeystore.setCertificateEntry(((X509Certificate) possibleRootCert).getSubjectDN().toString(), possibleRootCert);

                    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                    tmf.init(ssKeystore);

                    SSLContext ctx = SSLContext.getInstance("TLS");
                    ctx.init(null, tmf.getTrustManagers(), null);

                    conn.setSSLSocketFactory(ctx.getSocketFactory());
                } catch (Exception e) {
                    throw new WalletNameTlsaValidationException("Failed to Add TLSA Self Signed Certificate to HttpsURLConnection", e);
                }

            }
            ins = conn.getInputStream();
            isr = new InputStreamReader(ins);
            in = new BufferedReader(isr);

            String inputLine;
            String data = "";
            while ((inputLine = in.readLine()) != null) {
                data += inputLine;
            }

            try {
                return new BitcoinURI(data);
            } catch (BitcoinURIParseException e) {
                throw new WalletNameLookupException("Unable to create BitcoinURI", e);
            }
        } catch (IOException e) {
            throw new WalletNameURLFailedException("WalletName URL Connection Failed", e);
        } finally {
            if (conn != null && in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    // Do Nothing
                }
                conn.disconnect();
            }
        }
    }

    public String preprocessWalletName(String label) {
        if (label.contains("@")) {
            try {
                SHA224Digest md = new SHA224Digest();
                String[] emailParts = label.split("@", 2);
                md.update(emailParts[0].getBytes(), 0, emailParts[0].getBytes().length);
                byte[] hash = new byte[md.getDigestSize()];
                md.doFinal(hash, 0);
                String localPart = this.getHexString(hash);
                label = localPart + "." + emailParts[1];
            } catch (Exception e) {
                return label;
            }
        }
        return label;
    }

    private String getHexString(byte[] b) throws Exception {
        String result = "";
        for (byte aB : b) {
            result += Integer.toString((aB & 0xff) + 0x100, 16).substring(1);
        }
        return result;
    }

}

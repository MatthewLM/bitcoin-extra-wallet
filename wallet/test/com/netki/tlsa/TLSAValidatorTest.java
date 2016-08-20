package com.netki.tlsa;

import com.netki.dnssec.DNSSECResolver;
import com.netki.exceptions.DNSSECException;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.X509v3CertificateBuilder;
import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.generators.RSAKeyPairGenerator;
import org.spongycastle.crypto.params.RSAKeyGenerationParameters;
import org.spongycastle.crypto.params.RSAKeyParameters;
import org.spongycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.xbill.DNS.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateKeySpec;
import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest(TLSAValidator.class)
public class TLSAValidatorTest {

    private DNSSECResolver mockResolver;
    private CACertService caCertService;
    private CertChainValidator chainValidator;

    private TLSAValidator testObj;
    private TLSARecord testRecord;
    private List<Certificate> certs;
    private byte[] certData;

    @Before
    public void setUp() {
        this.mockResolver = mock(DNSSECResolver.class);
        this.caCertService = mock(CACertService.class);
        this.chainValidator = mock(CertChainValidator.class);

        // Add Certs to certs List
        try {
            certs = new ArrayList<Certificate>();
            certs.add(generateCertificate("CN=Test1, L=London, C=GB"));
            certs.add(generateCertificate("CN=Test2, L=London, C=GB"));
            certs.add(generateCertificate("CN=Test3, L=London, C=GB"));
        } catch (Exception e) {
            assertTrue("Exception Creating Test Certificates", false);
        }

        try {
            certData = new BigInteger("1bf4bfb2bfbf1e8bfbf1bfbfbfa7274b", 16).toByteArray();
            this.testRecord = new TLSARecord(new Name("_443._tcp.wallet.domain.com."), DClass.IN, 800, 0, 1, 2, certData);
        } catch (TextParseException e) {
            e.printStackTrace();
        }
    }

    @After
    public void tearDown() {
        reset(this.mockResolver);
        reset(this.caCertService);
        reset(this.chainValidator);
    }

    // Test Utility Functions

    /**
     * Create a self-signed X.509 Certificate
     *
     * @param dn the X.509 Distinguished Name, eg "CN=Test, L=London, C=GB"
     */
    private X509Certificate generateCertificate(String dn) throws Exception {

        X500Name x500nameIssuer = new X500Name("CN=TestCA,L=Den Haag, C=NL");
        X500Name x500nameSubject = new X500Name(dn);
        BigInteger serial = new BigInteger(64, new Random());
        Date notBefore = new Date();

        // Set Expiration Date
        Calendar tempCal = Calendar.getInstance();
        tempCal.setTime(notBefore);
        tempCal.add(Calendar.DATE, 365);
        Date notAfter = tempCal.getTime();

        // Create Pubkey
        RSAKeyPairGenerator keyGen = new RSAKeyPairGenerator();
        keyGen.init(new RSAKeyGenerationParameters(new BigInteger("10001", 16), SecureRandom.getInstance("SHA1PRNG"), 1024, 80));
        AsymmetricCipherKeyPair keys = keyGen.generateKeyPair();
        SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keys.getPublic());

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                x500nameIssuer,
                serial,
                notBefore,
                notAfter,
                Locale.US,
                x500nameSubject,
                subPubKeyInfo
        );

        try {
            // Export Private Key Info into Java PrivateKey
            BigInteger modulus = ((RSAKeyParameters) keys.getPrivate()).getModulus();
            BigInteger exponent = ((RSAKeyParameters) keys.getPrivate()).getExponent();
            RSAPrivateKeySpec privateSpec = new RSAPrivateKeySpec(modulus, exponent);
            KeyFactory factory = KeyFactory.getInstance("RSA");

            ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withRSA").build(factory.generatePrivate(privateSpec));

            X509CertificateHolder holder = builder.build(sigGen);
            InputStream is = new ByteArrayInputStream(holder.toASN1Structure().getEncoded());
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);

        } catch (OperatorCreationException e) {
            e.printStackTrace();
        }

        throw new Exception("Unable to Create Test X509 Cert");
    }

    /*
     * TEST:
     * TLSAValidator.validateTLSA()
     */
    @Test
    public void validateTLSA_CAConstraint_GoRight() {
        TLSAValidator testObj = mock(TLSAValidator.class);
        when(testObj.getTLSARecord(any(URL.class))).thenReturn(this.testRecord);
        when(testObj.getUrlCerts(any(URL.class))).thenReturn(certs);
        when(testObj.getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class))).thenReturn(certs.get(1));
        when(testObj.isValidCertChain(any(Certificate.class), anyListOf(Certificate.class))).thenReturn(true);

        try {
            when(testObj.validateTLSA(any(URL.class))).thenCallRealMethod();
        } catch (ValidSelfSignedCertException ve) {}

        try {
            boolean result = testObj.validateTLSA(new URL("https://wallet.domain.com"));
            assertTrue(result);

            verify(testObj).getTLSARecord(any(URL.class));
            verify(testObj).getUrlCerts(any(URL.class));
            verify(testObj).getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class));
            verify(testObj).isValidCertChain(any(Certificate.class), anyListOf(Certificate.class));
        } catch (Exception e) {
            e.printStackTrace();
            fail("Unknown Exception Occurred in Test");
        }
    }

    @Test
    public void validateTLSA_CAConstraint_MatchBaseCert() {
        TLSAValidator testObj = mock(TLSAValidator.class);
        when(testObj.getTLSARecord(any(URL.class))).thenReturn(this.testRecord);
        when(testObj.getUrlCerts(any(URL.class))).thenReturn(certs);
        when(testObj.getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class))).thenReturn(certs.get(0));
        when(testObj.isValidCertChain(any(Certificate.class), anyListOf(Certificate.class))).thenReturn(true);

        try {
            when(testObj.validateTLSA(any(URL.class))).thenCallRealMethod();
        } catch (ValidSelfSignedCertException ve) {}

        try {
            boolean result = testObj.validateTLSA(new URL("https://wallet.domain.com"));
            assertFalse(result);

            verify(testObj).getTLSARecord(any(URL.class));
            verify(testObj).getUrlCerts(any(URL.class));
            verify(testObj).getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class));
            verify(testObj).isValidCertChain(any(Certificate.class), anyListOf(Certificate.class));

        } catch (Exception e) {
            e.printStackTrace();
            fail("Unknown Exception Occurred in Test");
        }
    }

    @Test
    public void validateTLSA_CAConstraint_InvalidChain() {
        TLSAValidator testObj = mock(TLSAValidator.class);
        when(testObj.getTLSARecord(any(URL.class))).thenReturn(this.testRecord);
        when(testObj.getUrlCerts(any(URL.class))).thenReturn(certs);
        when(testObj.getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class))).thenReturn(certs.get(1));
        when(testObj.isValidCertChain(any(Certificate.class), anyListOf(Certificate.class))).thenReturn(false);

        try {
            when(testObj.validateTLSA(any(URL.class))).thenCallRealMethod();
        } catch (ValidSelfSignedCertException ve) {}

        try {
            boolean result = testObj.validateTLSA(new URL("https://wallet.domain.com"));
            assertFalse(result);

            verify(testObj).getTLSARecord(any(URL.class));
            verify(testObj).getUrlCerts(any(URL.class));
            verify(testObj).getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class));
            verify(testObj).isValidCertChain(any(Certificate.class), anyListOf(Certificate.class));

        } catch (Exception e) {
            e.printStackTrace();
            fail("Unknown Exception Occurred in Test");
        }
    }

    @Test
    public void validateTLSA_ServiceConstraint_GoRight() {

        try {
            this.testRecord = new TLSARecord(new Name("_443._tcp.wallet.domain.com."), DClass.IN, 800, 1, 1, 2, certData);
        } catch (TextParseException e) {
            e.printStackTrace();
        }

        TLSAValidator testObj = mock(TLSAValidator.class);
        when(testObj.getTLSARecord(any(URL.class))).thenReturn(this.testRecord);
        when(testObj.getUrlCerts(any(URL.class))).thenReturn(certs);
        when(testObj.getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class))).thenReturn(certs.get(0));
        when(testObj.isValidCertChain(any(Certificate.class), anyListOf(Certificate.class))).thenReturn(true);
        try {
            when(testObj.validateTLSA(any(URL.class))).thenCallRealMethod();
        } catch (ValidSelfSignedCertException ve) {}

        try {
            boolean result = testObj.validateTLSA(new URL("https://wallet.domain.com"));
            assertTrue(result);

            verify(testObj).getTLSARecord(any(URL.class));
            verify(testObj).getUrlCerts(any(URL.class));
            verify(testObj).getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class));
            verify(testObj).isValidCertChain(any(Certificate.class), anyListOf(Certificate.class));

        } catch (Exception e) {
            e.printStackTrace();
            fail("Unknown Exception Occurred in Test");
        }
    }

    @Test
    public void validateTLSA_ServiceConstraint_MatchCACert() {

        try {
            this.testRecord = new TLSARecord(new Name("_443._tcp.wallet.domain.com."), DClass.IN, 800, 1, 1, 2, certData);
        } catch (TextParseException e) {
            e.printStackTrace();
        }

        TLSAValidator testObj = mock(TLSAValidator.class);
        when(testObj.getTLSARecord(any(URL.class))).thenReturn(this.testRecord);
        when(testObj.getUrlCerts(any(URL.class))).thenReturn(certs);
        when(testObj.getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class))).thenReturn(certs.get(1));
        when(testObj.isValidCertChain(any(Certificate.class), anyListOf(Certificate.class))).thenReturn(true);
        try {
            when(testObj.validateTLSA(any(URL.class))).thenCallRealMethod();
        } catch (ValidSelfSignedCertException ve) {}

        try {
            boolean result = testObj.validateTLSA(new URL("https://wallet.domain.com"));
            assertFalse(result);

            verify(testObj).getTLSARecord(any(URL.class));
            verify(testObj).getUrlCerts(any(URL.class));
            verify(testObj).getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class));
            verify(testObj).isValidCertChain(any(Certificate.class), anyListOf(Certificate.class));

        } catch (Exception e) {
            e.printStackTrace();
            fail("Unknown Exception Occurred in Test");
        }
    }

    @Test
    public void validateTLSA_ServiceConstraint_InvalidChain() {

        try {
            this.testRecord = new TLSARecord(new Name("_443._tcp.wallet.domain.com."), DClass.IN, 800, 1, 1, 2, certData);
        } catch (TextParseException e) {
            e.printStackTrace();
        }

        TLSAValidator testObj = mock(TLSAValidator.class);
        when(testObj.getTLSARecord(any(URL.class))).thenReturn(this.testRecord);
        when(testObj.getUrlCerts(any(URL.class))).thenReturn(certs);
        when(testObj.getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class))).thenReturn(certs.get(0));
        when(testObj.isValidCertChain(any(Certificate.class), anyListOf(Certificate.class))).thenReturn(false);
        try {
            when(testObj.validateTLSA(any(URL.class))).thenCallRealMethod();
        } catch (ValidSelfSignedCertException ve) {}

        try {
            boolean result = testObj.validateTLSA(new URL("https://wallet.domain.com"));
            assertFalse(result);

            verify(testObj).getTLSARecord(any(URL.class));
            verify(testObj).getUrlCerts(any(URL.class));
            verify(testObj).getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class));
            verify(testObj).isValidCertChain(any(Certificate.class), anyListOf(Certificate.class));

        } catch (Exception e) {
            e.printStackTrace();
            fail("Unknown Exception Occurred in Test");
        }
    }

    @Test
    public void validateTLSA_TrustAnchor_GoRight() {

        try {
            this.testRecord = new TLSARecord(new Name("_443._tcp.wallet.domain.com."), DClass.IN, 800, 2, 1, 2, certData);
        } catch (TextParseException e) {
            e.printStackTrace();
        }

        TLSAValidator testObj = mock(TLSAValidator.class);
        when(testObj.getTLSARecord(any(URL.class))).thenReturn(this.testRecord);
        when(testObj.getUrlCerts(any(URL.class))).thenReturn(certs);
        when(testObj.getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class))).thenReturn(certs.get(2));
        when(testObj.isValidCertChain(any(Certificate.class), anyListOf(Certificate.class))).thenReturn(true);

        try {
            when(testObj.validateTLSA(any(URL.class))).thenCallRealMethod();
        } catch (ValidSelfSignedCertException ve) {
            assertTrue(false);
        }

        try {
            testObj.validateTLSA(new URL("https://wallet.domain.com"));
            assertTrue(false);
        } catch (ValidSelfSignedCertException ve) {
            assertEquals(ve.getRootCert(), certs.get(2));
            verify(testObj).getTLSARecord(any(URL.class));
            verify(testObj).getUrlCerts(any(URL.class));
            verify(testObj).getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class));
            verify(testObj).isValidCertChain(any(Certificate.class), anyListOf(Certificate.class));

        } catch (Exception e) {
            e.printStackTrace();
            fail("Unknown Exception Occurred in Test");
        }
    }

    @Test
    public void validateTLSA_TrustAnchor_MatchBaseCert() {

        try {
            this.testRecord = new TLSARecord(new Name("_443._tcp.wallet.domain.com."), DClass.IN, 800, 2, 1, 2, certData);
        } catch (TextParseException e) {
            e.printStackTrace();
        }

        TLSAValidator testObj = mock(TLSAValidator.class);
        when(testObj.getTLSARecord(any(URL.class))).thenReturn(this.testRecord);
        when(testObj.getUrlCerts(any(URL.class))).thenReturn(certs);
        when(testObj.getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class))).thenReturn(certs.get(0));
        when(testObj.isValidCertChain(any(Certificate.class), anyListOf(Certificate.class))).thenReturn(true);
        try {
            when(testObj.validateTLSA(any(URL.class))).thenCallRealMethod();
        } catch (ValidSelfSignedCertException ve) {}

        try {
            boolean result = testObj.validateTLSA(new URL("https://wallet.domain.com"));
            assertFalse(result);

            verify(testObj).getTLSARecord(any(URL.class));
            verify(testObj).getUrlCerts(any(URL.class));
            verify(testObj).getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class));
            verify(testObj).isValidCertChain(any(Certificate.class), anyListOf(Certificate.class));

        } catch (Exception e) {
            e.printStackTrace();
            fail("Unknown Exception Occurred in Test");
        }
    }

    @Test
    public void validateTLSA_TrustAnchor_InvalidChain() {

        try {
            this.testRecord = new TLSARecord(new Name("_443._tcp.wallet.domain.com."), DClass.IN, 800, 2, 1, 2, certData);
        } catch (TextParseException e) {
            e.printStackTrace();
        }

        TLSAValidator testObj = mock(TLSAValidator.class);
        when(testObj.getTLSARecord(any(URL.class))).thenReturn(this.testRecord);
        when(testObj.getUrlCerts(any(URL.class))).thenReturn(certs);
        when(testObj.getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class))).thenReturn(certs.get(2));
        when(testObj.isValidCertChain(any(Certificate.class), anyListOf(Certificate.class))).thenReturn(false);
        try {
            when(testObj.validateTLSA(any(URL.class))).thenCallRealMethod();
        } catch (ValidSelfSignedCertException ve) {}

        try {
            boolean result = testObj.validateTLSA(new URL("https://wallet.domain.com"));
            assertFalse(result);

            verify(testObj).getTLSARecord(any(URL.class));
            verify(testObj).getUrlCerts(any(URL.class));
            verify(testObj).getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class));
            verify(testObj).isValidCertChain(any(Certificate.class), anyListOf(Certificate.class));

        } catch (Exception e) {
            e.printStackTrace();
            fail("Unknown Exception Occurred in Test");
        }
    }

    @Test
    public void validateTLSA_DomainIssued_GoRight() {

        try {
            this.testRecord = new TLSARecord(new Name("_443._tcp.wallet.domain.com."), DClass.IN, 800, 3, 1, 2, certData);
        } catch (TextParseException e) {
            e.printStackTrace();
        }

        TLSAValidator testObj = mock(TLSAValidator.class);
        when(testObj.getTLSARecord(any(URL.class))).thenReturn(this.testRecord);
        when(testObj.getUrlCerts(any(URL.class))).thenReturn(certs);
        when(testObj.getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class))).thenReturn(certs.get(0));
        try {
            when(testObj.validateTLSA(any(URL.class))).thenCallRealMethod();
        } catch (ValidSelfSignedCertException ve) {}

        try {
            testObj.validateTLSA(new URL("https://wallet.domain.com"));
            assertFalse(true);
        } catch (ValidSelfSignedCertException vssc) {

            verify(testObj).getTLSARecord(any(URL.class));
            verify(testObj).getUrlCerts(any(URL.class));
            verify(testObj).getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class));
            verify(testObj, never()).isValidCertChain(any(Certificate.class), anyListOf(Certificate.class));

        } catch (Exception e) {
            e.printStackTrace();
            fail("Unknown Exception Occurred in Test");
        }
    }

    @Test
    public void validateTLSA_NullTLSARecord() {

        TLSAValidator testObj = mock(TLSAValidator.class);
        when(testObj.getTLSARecord(any(URL.class))).thenReturn(null);
        try {
            when(testObj.validateTLSA(any(URL.class))).thenCallRealMethod();
        } catch (ValidSelfSignedCertException ve) {}

        try {
            boolean result = testObj.validateTLSA(new URL("https://wallet.domain.com"));
            assertFalse(result);

            verify(testObj).getTLSARecord(any(URL.class));
            verify(testObj, never()).getUrlCerts(any(URL.class));
            verify(testObj, never()).getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class));
            verify(testObj, never()).isValidCertChain(any(Certificate.class), anyListOf(Certificate.class));

        } catch (Exception e) {
            e.printStackTrace();
            fail("Unknown Exception Occurred in Test");
        }
    }

    @Test
    public void validateTLSA_NullUrlCerts() {

        try {
            this.testRecord = new TLSARecord(new Name("_443._tcp.wallet.domain.com."), DClass.IN, 800, 3, 1, 2, certData);
        } catch (TextParseException e) {
            e.printStackTrace();
        }

        TLSAValidator testObj = mock(TLSAValidator.class);
        when(testObj.getTLSARecord(any(URL.class))).thenReturn(this.testRecord);
        when(testObj.getUrlCerts(any(URL.class))).thenReturn(null);
        try {
            when(testObj.validateTLSA(any(URL.class))).thenCallRealMethod();
        } catch (ValidSelfSignedCertException ve) {}

        try {
            boolean result = testObj.validateTLSA(new URL("https://wallet.domain.com"));
            assertFalse(result);

            verify(testObj).getTLSARecord(any(URL.class));
            verify(testObj).getUrlCerts(any(URL.class));
            verify(testObj, never()).getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class));
            verify(testObj, never()).isValidCertChain(any(Certificate.class), anyListOf(Certificate.class));

        } catch (Exception e) {
            e.printStackTrace();
            fail("Unknown Exception Occurred in Test");
        }
    }

    @Test
    public void validateTLSA_EmptyUrlCerts() {

        try {
            this.testRecord = new TLSARecord(new Name("_443._tcp.wallet.domain.com."), DClass.IN, 800, 3, 1, 2, certData);
        } catch (TextParseException e) {
            e.printStackTrace();
        }

        TLSAValidator testObj = mock(TLSAValidator.class);
        when(testObj.getTLSARecord(any(URL.class))).thenReturn(this.testRecord);
        when(testObj.getUrlCerts(any(URL.class))).thenReturn(new ArrayList<Certificate>());
        try {
            when(testObj.validateTLSA(any(URL.class))).thenCallRealMethod();
        } catch (ValidSelfSignedCertException ve) {}

        try {
            boolean result = testObj.validateTLSA(new URL("https://wallet.domain.com"));
            assertFalse(result);

            verify(testObj).getTLSARecord(any(URL.class));
            verify(testObj).getUrlCerts(any(URL.class));
            verify(testObj, never()).getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class));
            verify(testObj, never()).isValidCertChain(any(Certificate.class), anyListOf(Certificate.class));

        } catch (Exception e) {
            e.printStackTrace();
            fail("Unknown Exception Occurred in Test");
        }
    }

    @Test
    public void validateTLSA_NullMatchingCert() {

        try {
            this.testRecord = new TLSARecord(new Name("_443._tcp.wallet.domain.com."), DClass.IN, 800, 3, 1, 2, certData);
        } catch (TextParseException e) {
            e.printStackTrace();
        }

        TLSAValidator testObj = mock(TLSAValidator.class);
        when(testObj.getTLSARecord(any(URL.class))).thenReturn(this.testRecord);
        when(testObj.getUrlCerts(any(URL.class))).thenReturn(certs);
        when(testObj.getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class))).thenReturn(null);
        try {
            when(testObj.validateTLSA(any(URL.class))).thenCallRealMethod();
        } catch (ValidSelfSignedCertException ve) {}

        try {
            boolean result = testObj.validateTLSA(new URL("https://wallet.domain.com"));
            assertFalse(result);

            verify(testObj).getTLSARecord(any(URL.class));
            verify(testObj).getUrlCerts(any(URL.class));
            verify(testObj).getMatchingCert(any(TLSARecord.class), anyListOf(Certificate.class));
            verify(testObj, never()).isValidCertChain(any(Certificate.class), anyListOf(Certificate.class));

        } catch (Exception e) {
            e.printStackTrace();
            fail("Unknown Exception Occurred in Test");
        }
    }

    /*
     * TEST:
     * TLSAValidator.isValidCertChain()
     */
    @Test
    public void isValidCertChain_GoRight() {

        // Setup Mock Keystore
        KeyStore testKeyStore;

        // Setup Arg Certs
        List<Certificate> certList = new ArrayList<Certificate>();
        Certificate certList1;
        Certificate certList2;
        Certificate testCert;
        try {

            testKeyStore = spy(KeyStore.getInstance(KeyStore.getDefaultType()));
            Certificate cert1 = generateCertificate("CN=Test1, L=Los Angeles, C=US");
            testKeyStore.load(null);
            testKeyStore.setCertificateEntry("cert1", cert1);

            certList1 = generateCertificate("CN=Test, L=Los Angeles, C=US");
            certList2 = generateCertificate("CN=Test2, L=Los Angeles, C=US");
            certList.add(certList1);
            certList.add(certList2);

            testCert = generateCertificate("CN=TestCert, L=Los Angeles, C=US");
        } catch (Exception e) {
            fail("Test Setup Failure: " + e.getMessage());
            return;
        }

        try {
            PowerMockito.mockStatic(KeyStore.class);
            PowerMockito.when(KeyStore.getInstance(KeyStore.getDefaultType())).thenReturn(testKeyStore);
            when(this.caCertService.getCaCertKeystore()).thenReturn(testKeyStore);
            when(this.chainValidator.validateKeyChain(any(X509Certificate.class), any(KeyStore.class))).thenReturn(true);
        } catch (Exception e) {
            fail("Test Setup Failure: " + e.getMessage());
        }

        this.testObj = new TLSAValidator(this.mockResolver, this.caCertService, this.chainValidator);
        boolean result = false;
        try {
            result = this.testObj.isValidCertChain(testCert, certList);
        } catch (Exception e) {
            fail("Unexpected Exception Caught in Method Call: " + e.getMessage());
        }

        // Validate Test
        try {
            assertTrue(result);
            verify(this.caCertService, times(1)).getCaCertKeystore();
            //verify(testKeyStore, times(2)).setCertificateEntry(anyString(), any(Certificate.class));
            verify(this.chainValidator, times(1)).validateKeyChain(eq((X509Certificate) testCert), any(KeyStore.class));
        } catch (Exception e) {
            fail("Unexpected Exception Caught in Test Validation: " + e.getMessage());
        }

    }

    // TODO: Test Exception Case returns False

    /*
     * TEST:
     * getMatchingCert
     */
    @Test
    public void getMatchingCert_FullCert() {

        List<Certificate> certificateList = new ArrayList<Certificate>();

        // Setup Test
        try {
            certificateList.add(generateCertificate("CN=Test, L=London, C=GB"));
            this.testRecord = new TLSARecord(new Name("_443._tcp.wallet.domain.com."), DClass.IN, 800, 0, 0, 0, certificateList.get(0).getEncoded());
        } catch (Exception e) {
            fail("Test Setup Failure: " + e.getMessage());
        }

        // Test
        TLSAValidator testObj = new TLSAValidator(this.mockResolver, this.caCertService, this.chainValidator);
        Certificate result = testObj.getMatchingCert(this.testRecord, certificateList);
        assertEquals(result, certificateList.get(0));
    }

    @Test
    public void getMatchingCert_PubKey() {

        List<Certificate> certificateList = new ArrayList<Certificate>();

        // Setup Test
        try {
            certificateList.add(generateCertificate("CN=Test, L=London, C=GB"));
            this.testRecord = new TLSARecord(new Name("_443._tcp.wallet.domain.com."), DClass.IN, 800, 0, 1, 0, certificateList.get(0).getPublicKey().getEncoded());
        } catch (Exception e) {
            fail("Test Setup Failure: " + e.getMessage());
        }

        // Test
        TLSAValidator testObj = new TLSAValidator(this.mockResolver, this.caCertService, this.chainValidator);
        Certificate result = testObj.getMatchingCert(this.testRecord, certificateList);
        assertEquals(result, certificateList.get(0));
    }

    @Test
    public void getMatchingCert_SHA256() {

        List<Certificate> certificateList = new ArrayList<Certificate>();

        // Setup Test
        try {
            certificateList.add(generateCertificate("CN=Test, L=London, C=GB"));
            this.testRecord = new TLSARecord(new Name("_443._tcp.wallet.domain.com."), DClass.IN, 800, 0, 0, 1, MessageDigest.getInstance("SHA-256").digest(certificateList.get(0).getEncoded()));
        } catch (Exception e) {
            fail("Test Setup Failure: " + e.getMessage());
        }

        // Test
        TLSAValidator testObj = new TLSAValidator(this.mockResolver, this.caCertService, this.chainValidator);
        Certificate result = testObj.getMatchingCert(this.testRecord, certificateList);
        assertEquals(result, certificateList.get(0));
    }

    @Test
    public void getMatchingCert_SHA512() {

        List<Certificate> certificateList = new ArrayList<Certificate>();

        // Setup Test
        try {
            certificateList.add(generateCertificate("CN=Test, L=London, C=GB"));
            this.testRecord = new TLSARecord(new Name("_443._tcp.wallet.domain.com."), DClass.IN, 800, 0, 0, 2, MessageDigest.getInstance("SHA-512").digest(certificateList.get(0).getEncoded()));
        } catch (Exception e) {
            fail("Test Setup Failure: " + e.getMessage());
        }

        // Test
        TLSAValidator testObj = new TLSAValidator(this.mockResolver, this.caCertService, this.chainValidator);
        Certificate result = testObj.getMatchingCert(this.testRecord, certificateList);
        assertEquals(result, certificateList.get(0));
    }

    @Test
    public void getMatchingCert_NoMatch() {

        List<Certificate> certificateList = new ArrayList<Certificate>();

        // Setup Test
        try {
            certificateList.add(generateCertificate("CN=Test, L=London, C=GB"));
            Certificate notIncludedCert = generateCertificate("CN=Test2, L=London, C=GB");
            this.testRecord = new TLSARecord(new Name("_443._tcp.wallet.domain.com."), DClass.IN, 800, 0, 0, 0, notIncludedCert.getEncoded());
        } catch (Exception e) {
            fail("Test Setup Failure: " + e.getMessage());
        }

        // Test
        TLSAValidator testObj = new TLSAValidator(this.mockResolver, this.caCertService, this.chainValidator);
        Certificate result = testObj.getMatchingCert(this.testRecord, certificateList);
        assertNull(result);
    }

    /*
     * TEST:
     * TLSAValidator.getTLSARecord()
     */
    @Test
    public void getTLSARecordBaseURL() {

        // Setup Test
        URL submitUrl = null;
        String TLSAText = "0 1 2 1BF4BFB2BFBF1E8BFBF1BFBFBFA7274B";

        try {
            when(this.mockResolver.resolve("_443._tcp.wallet.domain.com.", Type.TLSA)).thenReturn(TLSAText);
            submitUrl = new URL("https://wallet.domain.com");
        } catch (Exception e) {
            e.printStackTrace();
            fail("Exception Setting up Test");
        }

        // Run Test
        testObj = new TLSAValidator(this.mockResolver, this.caCertService, this.chainValidator);
        TLSARecord result = testObj.getTLSARecord(submitUrl);

        assertEquals(0, result.getCertificateUsage());
        assertEquals(1, result.getSelector());
        assertEquals(2, result.getMatchingType());
        assertTrue(Arrays.equals(new BigInteger("1bf4bfb2bfbf1e8bfbf1bfbfbfa7274b", 16).toByteArray(), result.getCertificateAssociationData()));

        try {
            verify(this.mockResolver).resolve("_443._tcp.wallet.domain.com.", Type.TLSA);
        } catch (DNSSECException e) {
            e.printStackTrace();
            fail("Unexpected DNSSECException in Test");
        }
    }

    @Test
    public void getTLSARecordSpecificPort() {

        // Setup Test
        URL submitUrl = null;
        String TLSAText = "0 1 2 1BF4BFB2BFBF1E8BFBF1BFBFBFA7274B";

        try {
            when(this.mockResolver.resolve("_8181._tcp.wallet.domain.com.", Type.TLSA)).thenReturn(TLSAText);
            submitUrl = new URL("https://wallet.domain.com:8181");
        } catch (Exception e) {
            e.printStackTrace();
            fail("Exception Setting up Test");
        }

        // Run Test
        testObj = new TLSAValidator(this.mockResolver, this.caCertService, this.chainValidator);
        TLSARecord result = testObj.getTLSARecord(submitUrl);

        assertEquals(0, result.getCertificateUsage());
        assertEquals(1, result.getSelector());
        assertEquals(2, result.getMatchingType());
        assertTrue(Arrays.equals(new BigInteger("1bf4bfb2bfbf1e8bfbf1bfbfbfa7274b", 16).toByteArray(), result.getCertificateAssociationData()));

        try {
            verify(this.mockResolver).resolve("_8181._tcp.wallet.domain.com.", Type.TLSA);
        } catch (DNSSECException e) {
            e.printStackTrace();
            fail("Unexpected DNSSECException in Test");
        }
    }

    @Test
    public void getTLSARecordResolverFailure() {

        // Setup Test
        URL submitUrl = null;

        try {
            doThrow(new DNSSECException("ERROR")).when(this.mockResolver).resolve("_443._tcp.wallet.domain.com.", Type.TLSA);
            submitUrl = new URL("https://wallet.domain.com");
        } catch (Exception e) {
            e.printStackTrace();
            fail("Exception Setting up Test");
        }

        // Run Test
        testObj = new TLSAValidator(this.mockResolver, this.caCertService, this.chainValidator);
        TLSARecord result = testObj.getTLSARecord(submitUrl);
        assertNull(result);

        try {
            verify(this.mockResolver).resolve("_443._tcp.wallet.domain.com.", Type.TLSA);
        } catch (DNSSECException e) {
            e.printStackTrace();
            fail("Unexpected DNSSECException in Test");
        }
    }

    @Test
    public void getTLSARecordResolverEmptyResponse() {

        // Setup Test
        URL submitUrl = null;

        try {
            when(this.mockResolver.resolve("_443._tcp.wallet.domain.com.", Type.TLSA)).thenReturn("");
            submitUrl = new URL("https://wallet.domain.com");
        } catch (Exception e) {
            e.printStackTrace();
            fail("Exception Setting up Test");
        }

        // Run Test
        testObj = new TLSAValidator(this.mockResolver, this.caCertService, this.chainValidator);
        TLSARecord result = testObj.getTLSARecord(submitUrl);
        assertNull(result);

        try {
            verify(this.mockResolver).resolve("_443._tcp.wallet.domain.com.", Type.TLSA);
        } catch (DNSSECException e) {
            e.printStackTrace();
            fail("Unexpected DNSSECException in Test");
        }
    }

    @Test
    public void getTLSARecordTextParseException() {

        // Setup Test
        URL submitUrl = null;
        String TLSAText = "0 1 2 1bf4bfb2bfbf1e8bfbf1bfbfbf47274b";

        try {
            when(this.mockResolver.resolve("_443._tcp.wallet.domain..com.", Type.TLSA)).thenReturn(TLSAText);
            submitUrl = new URL("https://wallet.domain..com");
        } catch (Exception e) {
            e.printStackTrace();
            fail("Exception Setting up Test");
        }

        // Run Test
        testObj = new TLSAValidator(this.mockResolver, this.caCertService, this.chainValidator);
        TLSARecord result = testObj.getTLSARecord(submitUrl);
        assertNull(result);

        try {
            verify(this.mockResolver).resolve("_443._tcp.wallet.domain..com.", Type.TLSA);
        } catch (DNSSECException e) {
            e.printStackTrace();
            fail("Unexpected DNSSECException in Test");
        }
    }

}

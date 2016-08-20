package com.netki;

import com.netki.dnssec.DNSSECResolver;
import com.netki.exceptions.DNSSECException;
import com.netki.exceptions.WalletNameCurrencyUnavailableException;
import com.netki.exceptions.WalletNameDoesNotExistException;
import com.netki.exceptions.WalletNameLookupException;
import com.netki.tlsa.TLSAValidator;
import org.bitcoinj_extra.uri.BitcoinURI;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.xbill.DNS.Type;

import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Exchanger;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest(WalletNameResolver.class)
public class WalletNameResolverTest {

    private DNSSECResolver mockResolver;
    private TLSAValidator mockTlsaValidator;
    private WalletNameResolver testObj;

    @Before
    public void setUp() {
        this.mockResolver = mock(DNSSECResolver.class);
        this.mockTlsaValidator = mock(TLSAValidator.class);
        this.testObj = mock(WalletNameResolver.class);

        try {
            when(this.testObj.resolve(anyString(), anyString(), anyBoolean())).thenCallRealMethod();
            when(this.testObj.getAvailableCurrencies(anyString())).thenCallRealMethod();
            when(this.testObj.preprocessWalletName(anyString())).thenCallRealMethod();
            doCallRealMethod().when(this.testObj).setDNSSECResolver(any(DNSSECResolver.class));
            doCallRealMethod().when(this.testObj).setTlsaValidator(any(TLSAValidator.class));

            // Setup Backup
            doCallRealMethod().when(this.mockResolver).getBackupDnsServers();
            doCallRealMethod().when(this.mockResolver).setBackupDnsServers(any(List.class));
            doCallRealMethod().when(this.mockResolver).useBackupDnsServer(any(Integer.class));
            this.mockResolver.setBackupDnsServers(Arrays.asList("8.8.8.8", "8.8.4.4"));

            this.testObj.setDNSSECResolver(this.mockResolver);
            this.testObj.setTlsaValidator(this.mockTlsaValidator);
        } catch (WalletNameLookupException e) {
            e.printStackTrace();
        }
    }

    @After
    public void cleanUp() {
        reset(this.mockResolver);
        reset(this.mockTlsaValidator);
    }

    /*
     * Test getAvailableCurrencies()
     */
    @Test
    public void getAvailableCurrencies_GoRight() {
        try {
            when(this.mockResolver.resolve(eq("_wallet.wallet.domain.com."), eq(Type.TXT))).thenReturn("btc ltc");
        } catch (Exception e) {
            fail("Failure to Setup Test: " + e.getMessage());
        }

        try {
            List<String> currencies = this.testObj.getAvailableCurrencies("wallet.domain.com");
            assertNotNull(currencies);
            assertEquals(2, currencies.size());
            assertTrue(currencies.contains("btc"));
            assertTrue(currencies.contains("ltc"));
            assertFalse(currencies.contains("dgc"));
            verify(this.mockResolver, times(1)).resolve(eq("_wallet.wallet.domain.com."), eq(Type.TXT));
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

    @Test
    public void getAvailableCurrencies_EmptyResult() {
        try {
            when(this.mockResolver.resolve(eq("_wallet.wallet.domain.com."), eq(Type.TXT))).thenReturn("");
        } catch (Exception e) {
            fail("Failure to Setup Test: " + e.getMessage());
        }

        try {
            this.testObj.getAvailableCurrencies("wallet.domain.com");
            fail("Expected Exception");
        } catch (WalletNameDoesNotExistException e) {
            try {
                verify(this.mockResolver, times(1)).resolve(eq("_wallet.wallet.domain.com."), eq(Type.TXT));
            } catch (Exception e1) {

            }
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

    @Test
    public void getAvailableCurrencies_NullResult() {
        try {
            when(this.mockResolver.resolve(eq("_wallet.wallet.domain.com."), eq(Type.TXT))).thenReturn(null);
        } catch (Exception e) {
            fail("Failure to Setup Test: " + e.getMessage());
        }

        try {
            this.testObj.getAvailableCurrencies("wallet.domain.com");
            fail("Expected Exception");
        } catch (WalletNameDoesNotExistException e) {
            try {
                verify(this.mockResolver, times(1)).resolve(eq("_wallet.wallet.domain.com."), eq(Type.TXT));
            } catch (Exception e1) {

            }
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

    @Test
    public void getAvailableCurrencies_NonRetryableException() {
        try {
            when(this.mockResolver.resolve(eq("_wallet.wallet.domain.com."), eq(Type.TXT))).thenThrow(new DNSSECException("message"));
        } catch (Exception e) {
            fail("Failure to Setup Test: " + e.getMessage());
        }

        try {
            this.testObj.getAvailableCurrencies("wallet.domain.com");
            fail("Expected Exception");
        } catch (WalletNameLookupException e) {
            try {
                verify(this.mockResolver, times(3)).resolve(eq("_wallet.wallet.domain.com."), eq(Type.TXT));
                assertEquals("message", e.getMessage());
            } catch(Exception e1) {
                fail("Unknown Test Failure: " + e.getMessage());
            }
        }
    }

    @Test
    public void getAvailableCurrencies_RetriedException() {
        try {
            when(this.mockResolver.resolve(eq("_wallet.wallet.domain.com."), eq(Type.TXT))).thenThrow(new DNSSECException("message")).thenReturn("btc ltc");
        } catch (Exception e) {
            fail("Failure to Setup Test: " + e.getMessage());
        }

        try {
            List<String> currencies = this.testObj.getAvailableCurrencies("wallet.domain.com");
            assertNotNull(currencies);
            assertEquals(2, currencies.size());
            assertTrue(currencies.contains("btc"));
            assertTrue(currencies.contains("ltc"));
            assertFalse(currencies.contains("dgc"));
            verify(this.mockResolver, times(2)).resolve(eq("_wallet.wallet.domain.com."), eq(Type.TXT));
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

    /*
     * Test resolve()
     */

    @Test
    public void resolve_GoRightAddr() {
        try {
            when(this.mockResolver.resolve(eq("_btc._wallet.wallet.domain.com."), eq(Type.TXT))).thenReturn("1CpLXM15vjULK3ZPGUTDMUcGATGR9xGitv");
        } catch (Exception e) {
            fail("Failure to Setup Test: " + e.getMessage());
        }

        try {
            BitcoinURI result = this.testObj.resolve("wallet.domain.com", "btc", true);
            assertNotNull(result.getAddress());
            assertEquals("1CpLXM15vjULK3ZPGUTDMUcGATGR9xGitv", result.getAddress().toString());
            verify(this.mockResolver, times(1)).resolve(anyString(), eq(Type.TXT));
            verify(this.mockTlsaValidator, never()).validateTLSA(any(URL.class));
            verify(this.testObj, never()).processWalletNameUrl(any(URL.class), anyBoolean());
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

    @Test
    public void resolve_GoRightURL() {
        try {
            when(this.testObj.processWalletNameUrl(any(URL.class), anyBoolean())).thenReturn(new BitcoinURI("bitcoin:1CpLXM15vjULK3ZPGUTDMUcGATGR9xGitv"));
            when(this.mockResolver.resolve(eq("_btc._wallet.wallet.domain.com."), eq(Type.TXT))).thenReturn("aHR0cHM6Ly9hZGRyZXNzaW1vLm5ldGtpLmNvbS9yZXNvbHZlLzg3NTkzNDg3NTk0Mzc1OTQzNzk4MzQ3MzQ1");
        } catch (Exception e) {
            fail("Failure to Setup Test: " + e.getMessage());
        }

        try {
            BitcoinURI result = this.testObj.resolve("wallet.domain.com", "btc", true);
            assertNotNull(result.getAddress());
            assertEquals("1CpLXM15vjULK3ZPGUTDMUcGATGR9xGitv", result.getAddress().toString());
            verify(this.mockResolver, times(1)).resolve(anyString(), eq(Type.TXT));
            verify(this.mockTlsaValidator, never()).validateTLSA(any(URL.class));
            verify(this.testObj).processWalletNameUrl(eq(new URL("https://addressimo.netki.com/resolve/87593487594375943798347345")), anyBoolean());
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

    @Test
    public void resolve_EmptyLabel() {

        try {
            this.testObj.resolve("", "btc", true);
            fail("This should throw an exception");
        } catch (WalletNameLookupException e) {
            try {
                assertEquals("Wallet Name Label Must Non-Empty", e.getMessage());
                verify(this.mockResolver, never()).resolve(anyString(), eq(Type.TXT));
                verify(this.mockTlsaValidator, never()).validateTLSA(any(URL.class));
                verify(this.testObj, never()).processWalletNameUrl(any(URL.class), anyBoolean());
            } catch (Exception e1) {
                fail("Failure in Test Validation: " + e1.getMessage());
            }
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

    @Test
    public void resolve_CurrencyNotAvailable() {
        try {
            when(this.mockResolver.resolve(eq("_wallet.wallet.domain.com."), eq(Type.TXT))).thenReturn("btc ltc");
        } catch (Exception e) {
            fail("Failure to Setup Test: " + e.getMessage());
        }

        try {
            this.testObj.resolve("wallet.domain.com", "dgc", true);
            fail("This should throw an exception");
        } catch (WalletNameCurrencyUnavailableException e) {
            try {
                assertEquals("Currency Not Available in Wallet Name", e.getMessage());
                verify(this.mockResolver, times(1)).resolve(anyString(), eq(Type.TXT));
                verify(this.mockTlsaValidator, never()).validateTLSA(any(URL.class));
                verify(this.testObj, never()).processWalletNameUrl(any(URL.class), anyBoolean());
            } catch (Exception e1) {
                fail("Failure in Test Validation: " + e1.getMessage());
            }
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

    @Test
    public void resolve_EmptyAddressResolution() {
        try {
            when(this.mockResolver.resolve(eq("_btc._wallet.wallet.domain.com."), eq(Type.TXT))).thenReturn("");
        } catch (Exception e) {
            fail("Failure to Setup Test: " + e.getMessage());
        }

        try {
            this.testObj.resolve("wallet.domain.com", "btc", true);
            fail("This should throw an exception");
        } catch (WalletNameCurrencyUnavailableException e) {
            try {
                assertEquals("Currency Not Available in Wallet Name", e.getMessage());
                verify(this.mockResolver, times(1)).resolve(anyString(), eq(Type.TXT));
                verify(this.mockTlsaValidator, never()).validateTLSA(any(URL.class));
                verify(this.testObj, never()).processWalletNameUrl(any(URL.class), anyBoolean());
            } catch (Exception e1) {
                fail("Failure in Test Validation: " + e1.getMessage());
            }
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

    @Test
    public void resolve_ResolutionException() {
        try {
            when(this.mockResolver.resolve(eq("_btc._wallet.wallet.domain.com."), eq(Type.TXT))).thenThrow(new DNSSECException("message"));
        } catch (Exception e) {
            fail("Failure to Setup Test: " + e.getMessage());
        }

        try {
            this.testObj.resolve("wallet.domain.com", "btc", true);
            fail("This should throw an exception");
        } catch (WalletNameLookupException e) {
            try {
                assertEquals("message", e.getMessage());
                verify(this.mockResolver, times(3)).resolve(anyString(), eq(Type.TXT));
                verify(this.mockTlsaValidator, never()).validateTLSA(any(URL.class));
                verify(this.testObj, never()).processWalletNameUrl(any(URL.class), anyBoolean());
            } catch (Exception e1) {
                fail("Failure in Test Validation: " + e1.getMessage());
            }
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

    @Test
    public void resolve_ResolutionExceptionRetry() {
        try {
            when(this.mockResolver.resolve(eq("_btc._wallet.wallet.domain.com."), eq(Type.TXT))).thenThrow(new DNSSECException("message")).thenReturn("1CpLXM15vjULK3ZPGUTDMUcGATGR9xGitv");
        } catch (Exception e) {
            fail("Failure to Setup Test: " + e.getMessage());
        }

        try {
            BitcoinURI result = this.testObj.resolve("wallet.domain.com", "btc", true);
            assertNotNull(result.getAddress());
            assertEquals("1CpLXM15vjULK3ZPGUTDMUcGATGR9xGitv", result.getAddress().toString());
            verify(this.mockResolver, times(2)).resolve(anyString(), eq(Type.TXT));
            verify(this.mockTlsaValidator, never()).validateTLSA(any(URL.class));
            verify(this.testObj, never()).processWalletNameUrl(any(URL.class), anyBoolean());
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

    @Test
    public void resolve_URLException() {
        try {
            when(this.mockResolver.resolve(eq("_wallet.wallet.domain.com."), eq(Type.TXT))).thenReturn("btc ltc");
            when(this.mockResolver.resolve(eq("_btc._wallet.wallet.domain.com."), eq(Type.TXT))).thenReturn("1CpLXM15vjULK3ZPGUTDMUcGATGR9xGitv");
        } catch (Exception e) {
            fail("Failure to Setup Test: " + e.getMessage());
        }

        try {
            BitcoinURI result = this.testObj.resolve("wallet.domain.com", "btc", true);
            assertNotNull(result.getAddress());
            assertEquals("1CpLXM15vjULK3ZPGUTDMUcGATGR9xGitv", result.getAddress().toString());
            verify(this.mockResolver, times(1)).resolve(anyString(), eq(Type.TXT));
            verify(this.mockTlsaValidator, never()).validateTLSA(any(URL.class));
            verify(this.testObj, never()).processWalletNameUrl(eq(new URL("https://addressimo.netki.com/resolve/87593487594375943798347345")), anyBoolean());
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

    @Test
    public void preprocessWalletName_NonEmail() {
        try {
            String result = this.testObj.preprocessWalletName("user.domain.com");
            assertEquals("user.domain.com", result);
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

    @Test
    public void preprocessWalletName_Email() {
        try {
            String result = this.testObj.preprocessWalletName("user@domain.com");
            assertEquals("147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9.domain.com", result);
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

    @Test
    public void preprocessWalletName_EmailDoubleAt() {
        try {
            String result = this.testObj.preprocessWalletName("user@user@domain.com");
            assertEquals("147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9.user@domain.com", result);
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

}

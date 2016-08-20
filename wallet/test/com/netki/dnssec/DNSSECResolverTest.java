package com.netki.dnssec;

import com.netki.dns.DNSBootstrapService;
import com.netki.exceptions.DNSSECException;
import org.jitsi.dnssec.validator.ValidatingResolver;

import org.junit.Before;
import org.junit.After;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.xbill.DNS.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

public class DNSSECResolverTest {

    private DNSBootstrapService mockDNSBootstrapService;
    private SimpleResolver mockSimpleResolver;
    private ValidatingResolver mockValidatingResolver;
    private DNSSECResolver testObj;
    private Message responseMessage;
    private Header spyHeader;
    private Record answerRecord;

    @Before
    public void beforeTest() {

        // Setup Used Services
        this.mockDNSBootstrapService = mock(DNSBootstrapService.class);
        this.mockSimpleResolver = mock(SimpleResolver.class);
        this.mockValidatingResolver = mock(ValidatingResolver.class);

        // Setup GoRight Response
        this.responseMessage = spy(Message.class);
        this.spyHeader = spy(Header.class);
        this.responseMessage.setHeader(this.spyHeader);
        this.responseMessage.getHeader().setFlag(Flags.AD);
        this.responseMessage.getHeader().setRcode(Rcode.NOERROR);

        try {
            answerRecord = spy(new TXTRecord(new Name("wallet.domain.com."), DClass.IN, 86400L, "\"textresult\""));
        } catch (TextParseException e) {
            e.printStackTrace();
        }
        this.responseMessage.addRecord(answerRecord, Section.ANSWER);

        // Setup Mocks
        try {
            List<InetAddress> addrList = new ArrayList<InetAddress>();
            addrList.add(InetAddress.getByName("8.8.8.8"));

            when(this.mockDNSBootstrapService.getSystemDNSServers()).thenReturn(addrList);
            when(this.mockValidatingResolver.send(any(Message.class))).thenReturn(this.responseMessage);
        } catch (IOException e) {
            assertTrue("Exception Mocking Validating Resolver", false);
        }

        try {
            testObj = new DNSSECResolver(this.mockDNSBootstrapService);
            testObj.setSimpleResolver(this.mockSimpleResolver);
            testObj.setValidatingResolver(this.mockValidatingResolver);
        } catch (UnknownHostException e) {
            fail("UnknownHostException Caught");
        }
    }

    @After
    public void afterTest() {
        reset(this.mockDNSBootstrapService);
        reset(this.mockSimpleResolver);
        reset(this.mockValidatingResolver);
    }

    @Test
    public void testBackupDnsServers() {

        List<String> backupServers = testObj.getBackupDnsServers();

        assertEquals(2, backupServers.size());
        assertEquals("8.8.8.8", backupServers.get(0));
        assertEquals("8.8.4.4", backupServers.get(1));

        testObj.useBackupDnsServer(0);
        assertEquals("8.8.8.8", testObj.getSelectedDnsServer());

        testObj.useBackupDnsServer(1);
        assertEquals("8.8.4.4", testObj.getSelectedDnsServer());
    }

    @Test
    public void resolveGoRight() {
        try {
            String result = testObj.resolve("wallet.domain.com", Type.TXT);
            assertEquals("Text Record Value is Incorrect", "\\textresult\\", result);

            // Verify Calls
            verify(this.mockValidatingResolver).loadTrustAnchors(any(InputStream.class));
            verify(this.mockValidatingResolver, times(1)).send(any(Message.class));
            verify(this.responseMessage, atLeastOnce()).getHeader();
            verify(this.spyHeader).getFlag(Flags.AD);
            verify(this.responseMessage, times(1)).getSectionRRsets(Section.ANSWER);
            verify(this.answerRecord, times(1)).getType();
            verify(this.answerRecord, times(1)).rdataToString();
        } catch (Exception e) {
            e.printStackTrace();
            fail("Unexpected Exception Occurred");
        }
    }

    @Test
    public void resolveTrustAnchorUnknownHostException() {

        try {
            doThrow(new UnknownHostException()).when(this.mockValidatingResolver).loadTrustAnchors(any(InputStream.class));
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {

            String result = testObj.resolve("wallet.domain.com", Type.TXT);
            assertEquals("Text Record Value is Incorrect", "\\textresult\\", result);
            fail("resolve should throw DNSSEC Exception");
        } catch (Exception e) {
            if(e instanceof DNSSECException) {
                assertTrue(true);
                assertEquals("Unknown DNS Host: 8.8.8.8", e.getMessage());
                try {
                    verify(this.mockValidatingResolver).loadTrustAnchors(any(InputStream.class));
                    verify(this.mockValidatingResolver, times(0)).send(any(Message.class));
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        }
    }

    @Test
    public void resolveTrustAnchorUnsupportedEncodingException() {

        try {
            doThrow(new UnsupportedEncodingException()).when(this.mockValidatingResolver).loadTrustAnchors(any(InputStream.class));
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {

            String result = testObj.resolve("wallet.domain.com", Type.TXT);
            assertEquals("Text Record Value is Incorrect", "\\textresult\\", result);
            fail("resolve should throw DNSSEC Exception");
        } catch (Exception e) {
            if(e instanceof DNSSECException) {
                assertTrue(true);
                assertEquals("Unsupported Trust Anchor Encoding", e.getMessage());
                try {
                    verify(this.mockValidatingResolver).loadTrustAnchors(any(InputStream.class));
                    verify(this.mockValidatingResolver, times(0)).send(any(Message.class));
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        }
    }

    @Test
    public void resolveTrustAnchorIOException() {

        try {
            doThrow(new IOException("Error Message")).when(this.mockValidatingResolver).loadTrustAnchors(any(InputStream.class));
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {

            String result = testObj.resolve("wallet.domain.com", Type.TXT);
            assertEquals("Text Record Value is Incorrect", "\\textresult\\", result);
            fail("resolve should throw DNSSEC Exception");
        } catch (Exception e) {
            if(e instanceof DNSSECException) {
                assertTrue(true);
                assertEquals("Resolver Creation Exception: Error Message", e.getMessage());
                try {
                    verify(this.mockValidatingResolver).loadTrustAnchors(any(InputStream.class));
                    verify(this.mockValidatingResolver, times(0)).send(any(Message.class));
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        }
    }

    @Test
    public void resolveFlagNotAD() {

        this.spyHeader.unsetFlag(Flags.AD);
        this.responseMessage.removeAllRecords(Section.ANSWER);
        List<String> failList = new ArrayList<String>();
        failList.add("Failure Error 1");
        Record failRecord = new TXTRecord(Name.root, ValidatingResolver.VALIDATION_REASON_QCLASS, 800, failList);
        this.responseMessage.addRecord(failRecord, Section.ADDITIONAL);

        try {

            String result = testObj.resolve("wallet.domain.com", Type.TXT);
            assertEquals("Text Record Value is Incorrect", "\\textresult\\", result);
            fail("resolve should throw DNSSEC Exception");
        } catch (Exception e) {
            if(e instanceof DNSSECException) {
                assertTrue(true);
                assertEquals("Failure Error 1", e.getMessage());
                try {
                    verify(this.mockValidatingResolver).loadTrustAnchors(any(InputStream.class));
                    verify(this.mockValidatingResolver, times(1)).send(any(Message.class));
                    verify(this.spyHeader).getFlag(Flags.AD);
                    verify(this.responseMessage, times(0)).getSectionRRsets(Section.ANSWER);
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        }
    }

    @Test
    public void resolveRcodeSRVFAIL() {

        this.responseMessage.getHeader().setRcode(Rcode.SERVFAIL);
        this.responseMessage.removeAllRecords(Section.ANSWER);
        List<String> failList = new ArrayList<String>();
        failList.add("Failure Error 1");
        Record failRecord = new TXTRecord(Name.root, ValidatingResolver.VALIDATION_REASON_QCLASS, 800, failList);
        this.responseMessage.addRecord(failRecord, Section.ADDITIONAL);

        try {

            String result = testObj.resolve("wallet.domain.com", Type.TXT);
            assertEquals("Text Record Value is Incorrect", "\\textresult\\", result);
            fail("resolve should throw DNSSEC Exception");
        } catch (Exception e) {
            if(e instanceof DNSSECException) {
                assertTrue(true);
                assertEquals("Failure Error 1", e.getMessage());
                try {
                    verify(this.mockValidatingResolver).loadTrustAnchors(any(InputStream.class));
                    verify(this.mockValidatingResolver, times(1)).send(any(Message.class));
                    verify(this.spyHeader).getFlag(Flags.AD);
                    verify(this.responseMessage, times(1)).getRcode();
                    verify(this.responseMessage, times(0)).getSectionRRsets(Section.ANSWER);
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        }
    }

    @Test
    public void resolveNoAnswerReceived() {

        this.responseMessage.removeAllRecords(Section.ANSWER);
        List<String> failList = new ArrayList<String>();
        failList.add("Failure Error 1");
        Record failRecord = new TXTRecord(Name.root, ValidatingResolver.VALIDATION_REASON_QCLASS, 800, failList);
        this.responseMessage.addRecord(failRecord, Section.ADDITIONAL);

        try {

            testObj.resolve("wallet.domain.com", Type.TXT);
            fail("resolve should throw DNSSEC Exception");
        } catch (Exception e) {
            if(e instanceof DNSSECException) {
                assertTrue(true);
                assertEquals("No Query Answer Received", e.getMessage());
                try {
                    verify(this.mockValidatingResolver).loadTrustAnchors(any(InputStream.class));
                    verify(this.mockValidatingResolver, times(1)).send(any(Message.class));
                    verify(this.spyHeader).getFlag(Flags.AD);
                    verify(this.responseMessage, times(1)).getRcode();
                    verify(this.responseMessage, times(1)).getSectionRRsets(Section.ANSWER);
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        }
    }

    @Test
    public void resolveQueryIOError() {

        try {
            doThrow(new IOException("IO Failure")).when(this.mockValidatingResolver).send(any(Message.class));
        } catch (IOException e) {
            e.printStackTrace();
        }

        try {

            testObj.resolve("wallet.domain.com", Type.TXT);
            fail("resolve should throw DNSSEC Exception");
        } catch (Exception e) {
            if(e instanceof DNSSECException) {
                assertTrue(true);
                assertEquals("DNSSEC Lookup Failure: IO Failure", e.getMessage());
                try {
                    verify(this.mockValidatingResolver).loadTrustAnchors(any(InputStream.class));
                    verify(this.mockValidatingResolver, times(1)).send(any(Message.class));
                    verify(this.spyHeader, times(0)).getFlag(Flags.AD);
                    verify(this.responseMessage, times(0)).getRcode();
                    verify(this.responseMessage, times(0)).getSectionRRsets(Section.ANSWER);
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        }
    }

    @Test
    public void resolveNoAnswerNoAdditional() {

        this.spyHeader.unsetFlag(Flags.AD);
        this.spyHeader.setRcode(Rcode.SERVFAIL);
        this.responseMessage.removeAllRecords(Section.ANSWER);

        try {

            String result = testObj.resolve("wallet.domain.com", Type.TXT);
            assertNull(result);
        } catch (Exception e) {
            if(e instanceof DNSSECException) {
                assertTrue(true);
                assertEquals("Unknown DNSSEC Lookup Failure", e.getMessage());
                try {
                    verify(this.mockValidatingResolver).loadTrustAnchors(any(InputStream.class));
                    verify(this.mockValidatingResolver, times(1)).send(any(Message.class));
                    verify(this.spyHeader, times(1)).getFlag(Flags.AD);
                    verify(this.responseMessage, times(0)).getRcode();
                    verify(this.responseMessage, times(1)).getSectionRRsets(anyInt());
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        }
    }
}

package com.netki.dns;

import static org.junit.Assert.*;
import static org.powermock.api.mockito.PowerMockito.when;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.xbill.DNS.ResolverConfig;

import java.lang.reflect.Field;
import java.net.InetAddress;
import java.util.Hashtable;
import java.util.List;

@RunWith(PowerMockRunner.class)
@PrepareForTest(DNSBootstrapService.class)
public class DNSBootstrapServiceTest {

    @Test
    public void singleDnsServer() {

        String[] dnsServers = { "8.8.8.8" };

        try {
            ResolverConfig mockResolver = PowerMockito.mock(ResolverConfig.class);
            when(mockResolver.servers()).thenReturn(dnsServers);
            PowerMockito.whenNew(ResolverConfig.class).withNoArguments().thenReturn(mockResolver);
        } catch (Exception e) {
            fail("Test Setup Failed: " + e.toString());
        }

        DNSBootstrapService testService = new DNSBootstrapService();

        List<InetAddress> addrs = testService.getSystemDNSServers();

        assertEquals("Validate Addr Count", 1, addrs.size());
        assertEquals("Validate Address", "8.8.8.8", addrs.get(0).getHostAddress());
    }

    @Test
    public void multipleDnsServers() {

        String[] dnsServers = { "8.8.8.8", "8.8.4.4" };

        try {
            ResolverConfig mockResolver = PowerMockito.mock(ResolverConfig.class);
            when(mockResolver.servers()).thenReturn(dnsServers);
            PowerMockito.whenNew(ResolverConfig.class).withNoArguments().thenReturn(mockResolver);
        } catch (Exception e) {
            fail("Test Setup Failed: " + e.toString());
        }

        DNSBootstrapService testService = new DNSBootstrapService();
        List<InetAddress> addrs = testService.getSystemDNSServers();

        assertEquals("Validate Addr Count", 2, addrs.size());
        assertEquals("Validate Address", "8.8.8.8", addrs.get(0).getHostAddress());
        assertEquals("Validate Address", "8.8.4.4", addrs.get(1).getHostAddress());
    }

    @Test
    public void noDnsServers() {

        String[] dnsServers = { };

        try {
            ResolverConfig mockResolver = PowerMockito.mock(ResolverConfig.class);
            when(mockResolver.servers()).thenReturn(dnsServers);
            PowerMockito.whenNew(ResolverConfig.class).withNoArguments().thenReturn(mockResolver);
        } catch (Exception e) {
            fail("Test Setup Failed: " + e.toString());
        }

        DNSBootstrapService testService = new DNSBootstrapService();
        List<InetAddress> addrs = testService.getSystemDNSServers();

        assertEquals("Validate Addr Count", 0, addrs.size());
    }

}

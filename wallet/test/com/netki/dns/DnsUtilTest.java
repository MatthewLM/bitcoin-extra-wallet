package com.netki.dns;

import static org.junit.Assert.assertEquals;
import org.junit.Test;

public class DnsUtilTest {

    @Test
    public void TestEnsureDot() {
        assertEquals("Ensure Dot is Added", "test.com.", DNSUtil.ensureDot("test.com"));
        assertEquals("Ensure Dot is NOT Added", "test.com.", DNSUtil.ensureDot("test.com."));
    }

}

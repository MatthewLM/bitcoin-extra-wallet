package com.netki.dns;

public class DNSUtil {

    /**
     * Ensure a DNS label ends with a period
     *
     * @param label Given DNS label
     * @return DNS label that will always end with a period
     */
    public static String ensureDot(String label) {
        if(!label.endsWith(".")) {
            return label + ".";
        }
        return label;
    }
    
}

package com.netki.dns;

import org.xbill.DNS.ResolverConfig;

import java.net.InetAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

public class DNSBootstrapService {

    private Hashtable<?, ?> env;

    /**
     * Create DNSBootstrapService from system defaults
     */
    public DNSBootstrapService() {}

    /**
     * Get System DNS Servers
     * @return A list of InetAddress objects contains the system's configured DNS servers
     */
    public List<InetAddress> getSystemDNSServers() {

        List<InetAddress> dnsServers = new ArrayList<InetAddress>();
        ResolverConfig resolverConfig = new ResolverConfig();

        try {
            for(String dnsHostIp : resolverConfig.servers()) {
                if(dnsHostIp.equals("")) continue;
                dnsServers.add(InetAddress.getByName(dnsHostIp));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return dnsServers;
    }

}

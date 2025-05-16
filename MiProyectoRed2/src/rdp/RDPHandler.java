package com.miproyectored.rdp;

import java.util.HashMap;
import java.util.Map;
import java.io.*;
import java.net.Socket;

public class RDPHandler {
    private static final int RDP_PORT = 3389;
    private static final int TIMEOUT = 3000;

    public static class RDPResult {
        private String ipAddress;
        private Map<String, String> systemInfo;
        private boolean isAccessible;

        public RDPResult(String ipAddress) {
            this.ipAddress = ipAddress;
            this.systemInfo = new HashMap<>();
            this.isAccessible = false;
        }

        public void addInfo(String key, String value) {
            systemInfo.put(key, value);
        }

        public String getIpAddress() { return ipAddress; }
        public Map<String, String> getSystemInfo() { return systemInfo; }
        public boolean isAccessible() { return isAccessible; }
        public void setAccessible(boolean accessible) { isAccessible = accessible; }
    }

    public static RDPResult checkRDPAccess(String ipAddress) {
        RDPResult result = new RDPResult(ipAddress);
        
        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(ipAddress, RDP_PORT), TIMEOUT);
            result.setAccessible(true);
            result.addInfo("status", "Puerto RDP accesible");
            result.addInfo("port", String.valueOf(RDP_PORT));
            
            // Intentar obtener el nombre del host
            try {
                java.net.InetAddress addr = java.net.InetAddress.getByName(ipAddress);
                String hostname = addr.getHostName();
                if (!hostname.equals(ipAddress)) {
                    result.addInfo("hostname", hostname);
                }
            } catch (Exception e) {
                // Si no se puede obtener el hostname, lo ignoramos
            }
            
        } catch (IOException e) {
            result.setAccessible(false);
            result.addInfo("error", "Puerto RDP no accesible: " + e.getMessage());
        }
        
        return result;
    }
}
package com.miproyectored.webscan;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.io.*;
import java.security.cert.X509Certificate;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class WebScanner {
    private static final int TIMEOUT = 5000;
    private static final String[] COMMON_VULNERABILITIES = {
        "/admin", "/login", "/phpmyadmin", "/wp-admin",
        "/config", "/backup", "/.env", "/.git"
    };

    public static class WebScanResult {
        private String ipAddress;
        private Map<String, Object> securityInfo;
        private Map<String, Object> performanceInfo;
        private Map<String, Object> vulnerabilityInfo;

        public WebScanResult(String ipAddress) {
            this.ipAddress = ipAddress;
            this.securityInfo = new HashMap<>();
            this.performanceInfo = new HashMap<>();
            this.vulnerabilityInfo = new HashMap<>();
        }

        public void addSecurityInfo(String key, Object value) {
            securityInfo.put(key, value);
        }

        public void addPerformanceInfo(String key, Object value) {
            performanceInfo.put(key, value);
        }

        public void addVulnerabilityInfo(String key, Object value) {
            vulnerabilityInfo.put(key, value);
        }

        public String getIpAddress() { return ipAddress; }
        public Map<String, Object> getSecurityInfo() { return securityInfo; }
        public Map<String, Object> getPerformanceInfo() { return performanceInfo; }
        public Map<String, Object> getVulnerabilityInfo() { return vulnerabilityInfo; }
    }

    public static WebScanResult scanWebServices(String ipAddress) {
        WebScanResult result = new WebScanResult(ipAddress);
        
        try {
            // Configurar SSL para evitar errores de certificados
            configurarSSL();
            
            // Escanear puertos web comunes
            checkWebPort(result, "http", 80);
            checkWebPort(result, "https", 443);
            
            // Si hay servicios web, realizar análisis detallado
            if (result.getSecurityInfo().containsKey("http_enabled") || 
                result.getSecurityInfo().containsKey("https_enabled")) {
                
                // Análisis de vulnerabilidades comunes
                scanVulnerabilities(result);
                
                // Análisis de rendimiento
                measurePerformance(result);
                
                // Análisis de seguridad
                analyzeSecurity(result);
            }
            
        } catch (Exception e) {
            result.addSecurityInfo("error", "Error durante el escaneo: " + e.getMessage());
        }
        
        return result;
    }

    private static void checkWebPort(WebScanResult result, String protocol, int port) {
        String urlStr = protocol + "://" + result.getIpAddress() + ":" + port;
        try {
            URL url = new URL(urlStr);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(TIMEOUT);
            conn.setRequestMethod("HEAD");
            
            int responseCode = conn.getResponseCode();
            result.addSecurityInfo(protocol + "_enabled", true);
            result.addSecurityInfo(protocol + "_response_code", responseCode);
            result.addSecurityInfo(protocol + "_server", conn.getHeaderField("Server"));
            
        } catch (Exception e) {
            result.addSecurityInfo(protocol + "_enabled", false);
        }
    }

    private static void scanVulnerabilities(WebScanResult result) {
        for (String path : COMMON_VULNERABILITIES) {
            String urlStr = "http://" + result.getIpAddress() + path;
            try {
                URL url = new URL(urlStr);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setConnectTimeout(TIMEOUT);
                conn.setRequestMethod("HEAD");
                
                int responseCode = conn.getResponseCode();
                if (responseCode == 403) {
                    result.addVulnerabilityInfo(
                        "vulnerable_path_" + path,
                        "Acceso Denegado - Requiere autenticación (Código: 403)"
                    );
                } else if (responseCode == 401) {
                    result.addVulnerabilityInfo(
                        "vulnerable_path_" + path,
                        "No Autorizado - Requiere credenciales (Código: 401)"
                    );
                } else if (responseCode != 404) {
                    result.addVulnerabilityInfo(
                        "vulnerable_path_" + path,
                        "Accesible (Código: " + responseCode + ")"
                    );
                }
            } catch (Exception e) {
                result.addVulnerabilityInfo(
                    "vulnerable_path_" + path,
                    "Error de acceso: " + e.getMessage()
                );
            }
        }
    }

    private static void measurePerformance(WebScanResult result) {
        String urlStr = "http://" + result.getIpAddress();
        try {
            URL url = new URL(urlStr);
            long startTime = System.currentTimeMillis();
            
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(TIMEOUT);
            conn.connect();
            
            long endTime = System.currentTimeMillis();
            result.addPerformanceInfo("response_time_ms", endTime - startTime);
            
            // Analizar headers de rendimiento
            String cacheControl = conn.getHeaderField("Cache-Control");
            String contentEncoding = conn.getHeaderField("Content-Encoding");
            
            result.addPerformanceInfo("uses_caching", cacheControl != null);
            result.addPerformanceInfo("uses_compression", contentEncoding != null);
            
        } catch (Exception e) {
            result.addPerformanceInfo("error", "Error midiendo rendimiento: " + e.getMessage());
        }
    }

    private static void analyzeSecurity(WebScanResult result) {
        String urlStr = "https://" + result.getIpAddress();
        try {
            URL url = new URL(urlStr);
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setConnectTimeout(TIMEOUT);
            conn.connect();
            
            // Analizar certificado SSL
            X509Certificate[] certs = (X509Certificate[]) conn.getServerCertificates();
            if (certs.length > 0) {
                X509Certificate cert = certs[0];
                result.addSecurityInfo("ssl_valid_from", cert.getNotBefore());
                result.addSecurityInfo("ssl_valid_until", cert.getNotAfter());
                result.addSecurityInfo("ssl_issuer", cert.getIssuerDN().getName());
            }
            
            // Analizar headers de seguridad
            Map<String, String> securityHeaders = new HashMap<>();
            securityHeaders.put("X-Frame-Options", conn.getHeaderField("X-Frame-Options"));
            securityHeaders.put("X-XSS-Protection", conn.getHeaderField("X-XSS-Protection"));
            securityHeaders.put("X-Content-Type-Options", conn.getHeaderField("X-Content-Type-Options"));
            securityHeaders.put("Strict-Transport-Security", conn.getHeaderField("Strict-Transport-Security"));
            
            result.addSecurityInfo("security_headers", securityHeaders);
            
        } catch (Exception e) {
            result.addSecurityInfo("ssl_error", "Error analizando seguridad: " + e.getMessage());
        }
    }

    private static void configurarSSL() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };

            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
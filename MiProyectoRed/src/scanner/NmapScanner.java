package com.miproyectored.scanner;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class NmapScanner {
    private static final String NMAP_COMMAND = "nmap";

    public static class ScanResult {
        private String ip;
        private List<Integer> openPorts;
        private String hostName;

        public ScanResult(String ip) {
            this.ip = ip;
            this.openPorts = new ArrayList<>();
        }

        public void addPort(int port) {
            openPorts.add(port);
        }

        public String getIp() { return ip; }
        public List<Integer> getOpenPorts() { return openPorts; }
        public String getHostName() { return hostName; }
        public void setHostName(String hostName) { this.hostName = hostName; }
    }

    public static List<ScanResult> scanNetwork(String network) {
        List<ScanResult> results = new ArrayList<>();
        try {
            ProcessBuilder processBuilder = new ProcessBuilder(NMAP_COMMAND, "-sn", network);
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();

            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );

            String line;
            ScanResult currentResult = null;

            while ((line = reader.readLine()) != null) {
                if (line.contains("Nmap scan report for")) {
                    String ip = line.substring(line.lastIndexOf(" ") + 1);
                    currentResult = new ScanResult(ip);
                    results.add(currentResult);
                } else if (line.contains("Host is up") && currentResult != null) {
                    // Realizar un escaneo de puertos para hosts activos
                    scanPorts(currentResult);
                }
            }

            process.waitFor();
            reader.close();

        } catch (IOException | InterruptedException e) {
            System.err.println("Error durante el escaneo: " + e.getMessage());
            e.printStackTrace();
        }

        return results;
    }

    private static void scanPorts(ScanResult result) {
        try {
            ProcessBuilder processBuilder = new ProcessBuilder(
                NMAP_COMMAND, "-p-", "-T4", result.getIp()
            );
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();

            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );

            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("open")) {
                    String[] parts = line.split("/");
                    try {
                        int port = Integer.parseInt(parts[0].trim());
                        result.addPort(port);
                    } catch (NumberFormatException e) {
                        // Ignorar líneas que no contengan números de puerto válidos
                    }
                }
            }

            process.waitFor();
            reader.close();

        } catch (IOException | InterruptedException e) {
            System.err.println("Error durante el escaneo de puertos: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static List<String> parseResults(String nmapOutput) {
        List<String> activeHosts = new ArrayList<>();
        try {
            // Parsear la salida XML de Nmap
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(nmapOutput)));

            // Obtener todos los hosts
            NodeList hostList = doc.getElementsByTagName("host");
            
            // Procesar cada host
            for (int i = 0; i < hostList.getLength(); i++) {
                Node hostNode = hostList.item(i);
                if (hostNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element hostElement = (Element) hostNode;
                    NodeList addressList = hostElement.getElementsByTagName("address");
                    
                    // Obtener la dirección IP
                    for (int j = 0; j < addressList.getLength(); j++) {
                        Element addressElement = (Element) addressList.item(j);
                        if (addressElement.getAttribute("addrtype").equals("ipv4")) {
                            activeHosts.add(addressElement.getAttribute("addr"));
                            break;
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error al parsear resultados de Nmap: " + e.getMessage());
        }
        return activeHosts;
    }
}
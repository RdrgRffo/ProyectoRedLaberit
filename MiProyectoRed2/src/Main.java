package com.miproyectored;

import com.miproyectored.scanner.NmapScanner;
import com.miproyectored.ssh.SSHHandler;
import com.miproyectored.rdp.RDPHandler;
import com.miproyectored.snmp.SNMPHandler;
import com.miproyectored.webscan.WebScanner;
import com.miproyectored.normalization.DataNormalizer;
import com.miproyectored.report.ReportGenerator;

import java.net.*;
import java.util.*;
import java.util.stream.Collectors;

public class Main {
    private static List<String> detectLocalNetworks() {
        List<String> networks = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            
            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                
                if (!ni.isUp() || ni.isLoopback() || ni.isVirtual()) {
                    continue;
                }
                
                // Obtener las direcciones IP de la interfaz
                List<InterfaceAddress> addresses = ni.getInterfaceAddresses();
                for (InterfaceAddress addr : addresses) {
                    InetAddress inetAddr = addr.getAddress();
                    
                    if (inetAddr instanceof Inet4Address) {
                        short prefix = addr.getNetworkPrefixLength();
                        String ip = inetAddr.getHostAddress();
                        
                        // Calcular la dirección de red
                        String networkAddress = calculateNetworkAddress(ip, prefix);
                        String network = networkAddress + "/" + prefix;
                        
                        networks.add(network);
                        System.out.println("Interfaz: " + ni.getDisplayName());
                        System.out.println("Red detectada: " + network);
                    }
                }
            }
            
            if (networks.isEmpty()) {
                networks.add("192.168.1.0/24");
                System.out.println("No se detectaron redes, usando red por defecto: 192.168.1.0/24");
            }
            
        } catch (Exception e) {
            System.err.println("Error detectando redes: " + e.getMessage());
            networks.add("192.168.1.0/24");
        }
        return networks;
    }

    private static String calculateNetworkAddress(String ip, short prefix) {
        try {
            // Convertir IP a bytes
            String[] parts = ip.split("\\.");
            int[] bytes = new int[4];
            for (int i = 0; i < 4; i++) {
                bytes[i] = Integer.parseInt(parts[i]);
            }
            
            // Aplicar máscara de red
            int mask = -1 << (32 - prefix);
            int network = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) & mask;
            
            // Convertir de vuelta a formato string
            return String.format("%d.%d.%d.%d",
                (network >>> 24) & 0xFF,
                (network >>> 16) & 0xFF,
                (network >>> 8) & 0xFF,
                network & 0xFF);
        } catch (Exception e) {
            return ip;
        }
    }

    public static void main(String[] args) {
        System.out.println("=== MiProyectoRed - Escáner de Red ===\n");

        try {
            // Detectar todas las redes automáticamente
            List<String> networks = detectLocalNetworks();
            System.out.println("\nRedes detectadas:");
            networks.forEach(network -> System.out.println("- " + network));

            // Crear mapas para almacenar resultados
            Map<String, SSHHandler.SSHResult> sshResults = new HashMap<>();
            Map<String, SNMPHandler.SNMPResult> snmpResults = new HashMap<>();
            List<NmapScanner.ScanResult> allNmapResults = new ArrayList<>();
            
            // Escanear cada red detectada
            for (String network : networks) {
                System.out.println("\nIniciando escaneo de red: " + network);
                
                // Escaneo Nmap
                System.out.println("1. Escaneando dispositivos con Nmap...");
                List<NmapScanner.ScanResult> nmapResults = NmapScanner.scanNetwork(network);
                List<String> activeHosts = nmapResults.stream()
                    .map(NmapScanner.ScanResult::getIp)
                    .collect(Collectors.toList());
                
                System.out.println("\nHosts activos encontrados en " + network + ": " + activeHosts.size());
                
                // Escanear cada host activo
                for (String host : activeHosts) {
                    System.out.println("\nAnalizando host: " + host);
                    
                    // Escaneo SSH
                    SSHHandler.SSHResult sshResult = SSHHandler.getSystemInfo(host, "admin", "admin");
                    
                    // Escaneo RDP
                    RDPHandler.RDPResult rdpResult = RDPHandler.checkRDPAccess(host);
                    
                    // Escaneo SNMP
                    SNMPHandler.SNMPResult snmpResult = SNMPHandler.getDeviceInfo(host, "public");
                    
                    // Escaneo Web
                    WebScanner.WebScanResult webResult = WebScanner.scanWebServices(host);
                    
                    // Almacenar resultados en los mapas
                    sshResults.put(host, sshResult);
                    snmpResults.put(host, snmpResult);
                    
                    // Normalizar datos
                    DataNormalizer.addHostData(host, sshResult, rdpResult, 
                        snmpResult.getDeviceInfo().toString(), webResult);
                }
                
                allNmapResults.addAll(nmapResults);
            }
            
            // Generar informe final con todos los resultados
            System.out.println("\nGenerando informe final...");
            String jsonTempFile = "temp_report.json";
            String outputPath = "network_report.html";
            
            // Primero guardar los datos normalizados en un archivo temporal
            DataNormalizer.saveToFile(
                DataNormalizer.normalizeData(allNmapResults, sshResults, snmpResults),
                jsonTempFile
            );
            
            // Luego generar el informe HTML
            ReportGenerator.generateReport(jsonTempFile, outputPath);
            
            System.out.println("\nEscaneo completado. Revise el informe generado en: " + outputPath);

        } catch (Exception e) {
            System.err.println("Error durante la ejecución: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
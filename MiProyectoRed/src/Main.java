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
    private static String detectLocalNetwork() {
        try {
            // Obtener todas las interfaces de red
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            List<String> networks = new ArrayList<>();

            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                
                // Ignorar interfaces inactivas y loopback
                if (!ni.isUp() || ni.isLoopback()) {
                    continue;
                }

                // Obtener las direcciones IP de la interfaz
                Enumeration<InetAddress> addresses = ni.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    
                    // Solo considerar IPv4
                    if (addr instanceof Inet4Address) {
                        NetworkInterface network = NetworkInterface.getByInetAddress(addr);
                        short prefix = network.getInterfaceAddresses().get(0).getNetworkPrefixLength();
                        String ip = addr.getHostAddress();
                        networks.add(ip + "/" + prefix);
                    }
                }
            }

            // Mostrar las redes disponibles
            if (!networks.isEmpty()) {
                System.out.println("\nRedes detectadas:");
                for (int i = 0; i < networks.size(); i++) {
                    System.out.println((i + 1) + ". " + networks.get(i));
                }

                // Solicitar al usuario que elija una red
                Scanner scanner = new Scanner(System.in);
                System.out.print("\nSeleccione el número de la red a escanear (1-" + networks.size() + "): ");
                int choice = scanner.nextInt();
                
                if (choice > 0 && choice <= networks.size()) {
                    return networks.get(choice - 1);
                }
            }
            
            // Si no se encuentra ninguna red, usar una red por defecto
            return "192.168.1.0/24";
            
        } catch (Exception e) {
            System.err.println("Error detectando redes: " + e.getMessage());
            return "192.168.1.0/24";
        }
    }

    public static void main(String[] args) {
        System.out.println("=== MiProyectoRed - Escáner de Red ===\n");
        Scanner scanner = new Scanner(System.in);

        try {
            // Detectar y seleccionar red automáticamente
            String network = detectLocalNetwork();
            System.out.println("\nRed seleccionada: " + network);

            // Iniciar escaneo de red
            System.out.println("\nIniciando escaneo de red: " + network);
            
            // Escaneo Nmap
            System.out.println("1. Escaneando dispositivos con Nmap...");
            String nmapResults = NmapScanner.runNmap(network);
            
            // Procesar resultados y crear lista de dispositivos
            List<String> activeHosts = NmapScanner.parseResults(nmapResults);
            
            // Escanear cada host activo
            for (String host : activeHosts) {
                System.out.println("\nAnalizando host: " + host);
                
                // Escaneo SSH
                SSHHandler.SSHResult sshResult = SSHHandler.checkSSH(host);
                
                // Escaneo RDP
                RDPHandler.RDPResult rdpResult = RDPHandler.checkRDPAccess(host);
                
                // Escaneo SNMP
                String snmpResult = SNMPHandler.getSNMPData(host, "public");
                
                // Escaneo Web
                WebScanner.WebScanResult webResult = WebScanner.scanWebServices(host);
                
                // Normalizar datos
                DataNormalizer.addHostData(host, sshResult, rdpResult, snmpResult, webResult);
            }
            
            // Generar informe final
            System.out.println("\nGenerando informe...");
            ReportGenerator.generateReport(DataNormalizer.getFullReport());
            
            System.out.println("\nEscaneo completado. Revise el informe generado.");

        } catch (Exception e) {
            System.err.println("Error durante la ejecución: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}
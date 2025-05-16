package com.miproyectored.normalization;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.miproyectored.scanner.NmapScanner.ScanResult;
import com.miproyectored.ssh.SSHHandler.SSHResult;
import com.miproyectored.snmp.SNMPHandler.SNMPResult;

import java.util.List;
import java.util.Map;

public class DataNormalizer {
    private static final ObjectMapper mapper = new ObjectMapper();
    private static Map<String, Map<String, Object>> hostData = new HashMap<>();

    public static String normalizeData(
            List<ScanResult> nmapResults,
            Map<String, SSHResult> sshResults,
            Map<String, SNMPResult> snmpResults) {
        
        try {
            ObjectNode rootNode = mapper.createObjectNode();
            ArrayNode devicesArray = mapper.createArrayNode();

            // Procesar resultados de Nmap
            for (ScanResult scanResult : nmapResults) {
                ObjectNode deviceNode = mapper.createObjectNode();
                deviceNode.put("ip", scanResult.getIp());
                
                // Agregar puertos abiertos
                ArrayNode portsArray = mapper.createArrayNode();
                for (Integer port : scanResult.getOpenPorts()) {
                    portsArray.add(port);
                }
                deviceNode.set("open_ports", portsArray);

                // Agregar información SSH si está disponible
                SSHResult sshResult = sshResults.get(scanResult.getIp());
                if (sshResult != null) {
                    ObjectNode sshNode = mapper.createObjectNode();
                    for (Map.Entry<String, String> entry : sshResult.getSystemInfo().entrySet()) {
                        sshNode.put(entry.getKey(), entry.getValue());
                    }
                    deviceNode.set("ssh_info", sshNode);
                }

                // Agregar información SNMP si está disponible
                SNMPResult snmpResult = snmpResults.get(scanResult.getIp());
                if (snmpResult != null) {
                    ObjectNode snmpNode = mapper.createObjectNode();
                    for (Map.Entry<String, String> entry : snmpResult.getDeviceInfo().entrySet()) {
                        snmpNode.put(entry.getKey(), entry.getValue());
                    }
                    deviceNode.set("snmp_info", snmpNode);
                }

                devicesArray.add(deviceNode);
            }

            rootNode.set("devices", devicesArray);
            return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(rootNode);

        } catch (Exception e) {
            System.err.println("Error al normalizar datos: " + e.getMessage());
            return "{\"error\": \"Error al normalizar datos\"}";
        }
    }

    public static void saveToFile(String jsonData, String filePath) {
        try {
            mapper.writerWithDefaultPrettyPrinter()
                  .writeValue(new java.io.File(filePath), 
                             mapper.readTree(jsonData));
        } catch (Exception e) {
            System.err.println("Error al guardar JSON: " + e.getMessage());
        }
    }

    public static void addHostData(String host, SSHHandler.SSHResult ssh, 
                                 RDPHandler.RDPResult rdp, 
                                 String snmp, 
                                 WebScanner.WebScanResult web) {
        Map<String, Object> hostInfo = new HashMap<>();
        hostInfo.put("ssh", ssh);
        hostInfo.put("rdp", rdp);
        hostInfo.put("snmp", snmp);
        hostInfo.put("web", web);
        hostData.put(host, hostInfo);
    }

    public static Map<String, Map<String, Object>> getFullReport() {
        return hostData;
    }
}
package com.miproyectored.snmp;

import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.util.HashMap;
import java.util.Map;

public class SNMPHandler {
    private static final int SNMP_PORT = 161;
    private static final int TIMEOUT = 1000;
    private static final int RETRIES = 2;

    public static class SNMPResult {
        private String ipAddress;
        private Map<String, String> deviceInfo;

        public SNMPResult(String ipAddress) {
            this.ipAddress = ipAddress;
            this.deviceInfo = new HashMap<>();
        }

        public void addInfo(String key, String value) {
            deviceInfo.put(key, value);
        }

        public String getIpAddress() { return ipAddress; }
        public Map<String, String> getDeviceInfo() { return deviceInfo; }
    }

    public static SNMPResult getDeviceInfo(String ipAddress, String community) {
        SNMPResult result = new SNMPResult(ipAddress);

        try {
            TransportMapping transport = new DefaultUdpTransportMapping();
            Snmp snmp = new Snmp(transport);
            transport.listen();

            // Configurar el target
            CommunityTarget target = new CommunityTarget();
            target.setCommunity(new OctetString(community));
            target.setVersion(SnmpConstants.version2c);
            target.setAddress(new UdpAddress(ipAddress + "/" + SNMP_PORT));
            target.setTimeout(TIMEOUT);
            target.setRetries(RETRIES);

            // OIDs comunes para obtener información del dispositivo
            Map<String, String> oids = new HashMap<>();
            oids.put("sysDescr", ".1.3.6.1.2.1.1.1.0");      // Descripción del sistema
            oids.put("sysUpTime", ".1.3.6.1.2.1.1.3.0");    // Tiempo de actividad
            oids.put("sysContact", ".1.3.6.1.2.1.1.4.0");   // Contacto del sistema
            oids.put("sysName", ".1.3.6.1.2.1.1.5.0");      // Nombre del sistema
            oids.put("sysLocation", ".1.3.6.1.2.1.1.6.0");  // Ubicación del sistema

            // Consultar cada OID
            for (Map.Entry<String, String> entry : oids.entrySet()) {
                PDU pdu = new PDU();
                pdu.add(new VariableBinding(new OID(entry.getValue())));
                pdu.setType(PDU.GET);

                ResponseEvent response = snmp.get(pdu, target);

                if (response != null && response.getResponse() != null) {
                    PDU responsePDU = response.getResponse();
                    if (responsePDU.getErrorStatus() == PDU.noError) {
                        String value = responsePDU.getVariableBindings().firstElement().getVariable().toString();
                        result.addInfo(entry.getKey(), value);
                    }
                }
            }

            snmp.close();

        } catch (Exception e) {
            System.err.println("Error SNMP para " + ipAddress + ": " + e.getMessage());
            result.addInfo("error", e.getMessage());
        }

        return result;
    }

    public static boolean isSnmpEnabled(String ipAddress, String community) {
        try {
            TransportMapping transport = new DefaultUdpTransportMapping();
            Snmp snmp = new Snmp(transport);
            transport.listen();

            CommunityTarget target = new CommunityTarget();
            target.setCommunity(new OctetString(community));
            target.setVersion(SnmpConstants.version2c);
            target.setAddress(new UdpAddress(ipAddress + "/" + SNMP_PORT));
            target.setTimeout(TIMEOUT);
            target.setRetries(1);

            PDU pdu = new PDU();
            pdu.add(new VariableBinding(new OID(".1.3.6.1.2.1.1.1.0")));
            pdu.setType(PDU.GET);

            ResponseEvent response = snmp.get(pdu, target);
            snmp.close();

            return response != null && response.getResponse() != null;

        } catch (Exception e) {
            return false;
        }
    }
}
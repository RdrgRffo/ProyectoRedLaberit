package com.miproyectored.report;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class ReportGenerator {
    private static final String CSS_STYLES = """
            <style>
            body {
                font-family: 'Segoe UI', Arial, sans-serif;
                line-height: 1.6;
                margin: 0;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background-color: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            h1 {
                color: #2c3e50;
                text-align: center;
                padding-bottom: 10px;
                border-bottom: 2px solid #3498db;
            }
            .device {
                margin: 20px 0;
                padding: 15px;
                border: 1px solid #ddd;
                border-radius: 4px;
                background-color: #fff;
            }
            .device h2 {
                color: #3498db;
                margin-top: 0;
            }
            .info-section {
                margin: 10px 0;
                padding: 10px;
                background-color: #f8f9fa;
                border-radius: 4px;
            }
            .info-section h3 {
                color: #2c3e50;
                margin-top: 0;
            }
            .ports {
                display: flex;
                flex-wrap: wrap;
                gap: 5px;
            }
            .port {
                background-color: #3498db;
                color: white;
                padding: 3px 8px;
                border-radius: 3px;
                font-size: 0.9em;
            }
            .timestamp {
                text-align: center;
                color: #666;
                font-size: 0.9em;
                margin-top: 20px;
            }
            </style>
            """;

    public static void generateReport(String jsonFilePath, String outputPath) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode rootNode = mapper.readTree(new File(jsonFilePath));
            
            StringBuilder html = new StringBuilder();
            html.append("<!DOCTYPE html>\n")
                .append("<html lang=\"es\">\n")
                .append("<head>\n")
                .append("    <meta charset=\"UTF-8\">\n")
                .append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n")
                .append("    <title>Informe de Escaneo de Red</title>\n")
                .append(CSS_STYLES)
                .append("</head>\n")
                .append("<body>\n")
                .append("<div class=\"container\">\n")
                .append("    <h1>Informe de Escaneo de Red</h1>\n");

            JsonNode devices = rootNode.get("devices");
            if (devices != null && devices.isArray()) {
                for (JsonNode device : devices) {
                    html.append(generateDeviceSection(device));
                }
            }

            // Agregar timestamp
            LocalDateTime now = LocalDateTime.now();
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");
            html.append("    <div class=\"timestamp\">Informe generado el ")
                .append(now.format(formatter))
                .append("</div>\n");

            html.append("</div>\n")
                .append("</body>\n")
                .append("</html>");

            // Guardar el archivo HTML
            try (FileWriter writer = new FileWriter(outputPath)) {
                writer.write(html.toString());
            }

        } catch (IOException e) {
            System.err.println("Error al generar el informe: " + e.getMessage());
        }
    }

    private static String generateDeviceSection(JsonNode device) {
        StringBuilder section = new StringBuilder();
        section.append("    <div class=\"device\">\n")
               .append("        <h2>Dispositivo: ").append(device.get("ip").asText()).append("</h2>\n");

        // Puertos abiertos
        JsonNode ports = device.get("open_ports");
        if (ports != null && ports.isArray() && ports.size() > 0) {
            section.append("        <div class=\"info-section\">\n")
                   .append("            <h3>Puertos Abiertos</h3>\n")
                   .append("            <div class=\"ports\">\n");
            
            for (JsonNode port : ports) {
                section.append("                <span class=\"port\">").append(port.asText()).append("</span>\n");
            }
            
            section.append("            </div>\n")
                   .append("        </div>\n");
        }

        // Información SSH
        JsonNode sshInfo = device.get("ssh_info");
        if (sshInfo != null && sshInfo.isObject()) {
            section.append("        <div class=\"info-section\">\n")
                   .append("            <h3>Información SSH</h3>\n");
            
            sshInfo.fields().forEachRemaining(entry -> {
                section.append("            <p><strong>")
                       .append(entry.getKey())
                       .append(":</strong> ")
                       .append(entry.getValue().asText())
                       .append("</p>\n");
            });
            
            section.append("        </div>\n");
        }

        // Información SNMP
        JsonNode snmpInfo = device.get("snmp_info");
        if (snmpInfo != null && snmpInfo.isObject()) {
            section.append("        <div class=\"info-section\">\n")
                   .append("            <h3>Información SNMP</h3>\n");
            
            snmpInfo.fields().forEachRemaining(entry -> {
                section.append("            <p><strong>")
                       .append(entry.getKey())
                       .append(":</strong> ")
                       .append(entry.getValue().asText())
                       .append("</p>\n");
            });
            
            section.append("        </div>\n");
        }

        section.append("    </div>\n");
        return section.toString();
    }
}
package com.miproyectored;

import com.miproyectored.model.Device;
import com.miproyectored.model.NetworkReport;
import com.miproyectored.scanner.NmapScanner;
import com.miproyectored.util.NetworkUtils;
// Asegúrate de crear estas clases e importarlas correctamente
// import com.miproyectored.inventory.InventoryManager; // Aún no lo usamos
import com.miproyectored.export.JsonExporter; // <--- AÑADIR ESTA IMPORTACIÓN

import java.util.ArrayList; // Para el fallback
import java.util.List;
import java.util.Map;
import java.util.Date; // Para new java.util.Date

public class Main {

    public static void main(String[] args) {
        System.out.println("Iniciando MiProyectoRed...");

        // 1. Instanciar componentes principales
        NmapScanner scanner = new NmapScanner();
        // InventoryManager inventoryManager = new InventoryManager(); // Descomenta cuando la clase exista
        JsonExporter jsonExporter = new JsonExporter();             // <--- DESCOMENTAR E INSTANCIAR

        // 2. Detectar redes locales para escanear
        List<String> networksToScan = NetworkUtils.detectLocalNetworks();

        if (networksToScan == null || networksToScan.isEmpty()) {
            System.out.println("No se pudieron detectar redes locales automáticamente.");
            // Fallback: escanear solo la máquina local o una red predeterminada
            networksToScan = new ArrayList<>(); // Inicializar para evitar NullPointerException
            networksToScan.add("localhost"); // O tu red por defecto como "10.0.0.0/24"
            System.out.println("Se escaneará '" + networksToScan.get(0) + "' como objetivo por defecto.");
            // System.out.println("No hay redes para escanear. Finalizando.");
            // return; // Decide si quieres terminar o usar el fallback
        }

        System.out.println("Se escanearán las siguientes redes/objetivos: " + networksToScan);

        int reportCounter = 1; // Para nombres de archivo únicos si hay múltiples reportes

        for (String targetNetwork : networksToScan) {
            System.out.println("\n========================================================");
            System.out.println("Iniciando escaneo para el objetivo: " + targetNetwork);
            System.out.println("========================================================");

            // 3. Ejecutar el escaneo para el objetivo actual
            List<Device> detectedDevices = scanner.scan(targetNetwork);

            // 4. Crear y poblar el NetworkReport
            NetworkReport report = new NetworkReport();
            report.setScannedNetworkTarget(targetNetwork);
            // Podrías obtener la versión de Nmap del scanner si la expone,
            // o directamente del XML si modificas el POJO NmapRun para capturarla.
            // report.setScanEngineInfo(scanner.getNmapVersion()); // Suponiendo que NmapScanner expone la versión

            if (detectedDevices != null) {
                for (Device device : detectedDevices) {
                    report.addDevice(device);
                }
            }

            // 5. Guardar el reporte usando InventoryManager (cuando esté implementado)
            // System.out.println("\n--- Guardando Reporte en Inventario ---");
            // inventoryManager.saveReport(report);
            // System.out.println("Reporte para " + targetNetwork + " guardado.");

            // 6. Exportar el reporte a JSON
            System.out.println("\n--- Exportando Reporte a JSON ---");
            String jsonReportString = jsonExporter.exportReportToJsonString(report); // <--- OBTENER JSON COMO STRING
            System.out.println("Contenido JSON del Reporte para " + targetNetwork + ":");
            System.out.println(jsonReportString); // <--- MOSTRAR JSON EN CONSOLA

            // Opcional: Guardar el reporte JSON en un archivo
            // Crear un nombre de archivo descriptivo. Reemplazar caracteres no válidos para nombres de archivo.
            String safeTargetNetworkName = targetNetwork.replaceAll("[^a-zA-Z0-9.-]", "_");
            String reportFileName = "reporte_escaneo_" + safeTargetNetworkName + "_" + reportCounter + ".json";
            jsonExporter.exportReportToFile(report, reportFileName); // <--- GUARDAR JSON EN ARCHIVO
            reportCounter++;


            // 7. Mostrar los resultados del reporte actual en consola (resumen)
            System.out.println("\n--- Reporte del Escaneo para: " + report.getScannedNetworkTarget() + " ---");
            System.out.println("Fecha del escaneo: " + new Date(report.getScanTimestamp()));
            System.out.println("Objetivo: " + report.getScannedNetworkTarget());
            System.out.println("Dispositivos encontrados: " + report.getDeviceCount());

            if (report.getDevices() != null && !report.getDevices().isEmpty()) {
                System.out.println("\nDetalles de los dispositivos:");
                for (Device device : report.getDevices()) {
                    System.out.println("------------------------------------");
                    System.out.println("  IP: " + device.getIp());
                    if (device.getHostname() != null && !device.getHostname().isEmpty()) {
                        System.out.println("  Hostname: " + device.getHostname());
                    }
                    if (device.getMac() != null && !device.getMac().isEmpty()) {
                        System.out.println("  MAC: " + device.getMac() +
                                           (device.getManufacturer() != null ? " (" + device.getManufacturer() + ")" : ""));
                    }
                    if (device.getOs() != null && !device.getOs().isEmpty()) {
                        System.out.println("  OS: " + device.getOs());
                    }
                    if (device.getOpenPorts() != null && !device.getOpenPorts().isEmpty()) {
                        System.out.println("  Puertos abiertos: " + device.getOpenPorts());
                        if (device.getServices() != null && !device.getServices().isEmpty()) {
                            System.out.println("  Servicios detectados: ");
                            for (Map.Entry<Integer, String> entry : device.getServices().entrySet()) {
                                System.out.println("    - Puerto " + entry.getKey() + ": " + entry.getValue());
                            }
                        } else {
                             System.out.println("  No se detectaron servicios detallados para los puertos abiertos.");
                        }
                    } else {
                        System.out.println("  No se detectaron puertos abiertos.");
                    }
                }
                System.out.println("------------------------------------");
            } else {
                System.out.println("No se encontraron dispositivos activos o con información relevante para " + targetNetwork + ".");
            }
            System.out.println("\nEscaneo para " + targetNetwork + " finalizado.");
        }

        System.out.println("\n========================================================");
        System.out.println("Todos los escaneos han finalizado.");
        System.out.println("========================================================");

        // Próximos pasos podrían incluir:
        // - Implementar InventoryManager para persistencia real (BD, archivos).
        // - Implementar RiskAnalyzer.
    }
}
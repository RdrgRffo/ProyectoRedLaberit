package com.miproyectored.export;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.miproyectored.model.NetworkReport;

import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;

public class JsonExporter {

    private ObjectMapper objectMapper;

    public JsonExporter() {
        this.objectMapper = new ObjectMapper();
        // Configurar para que el JSON sea legible (pretty print)
        this.objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
        // Opcional: Configurar el formato de fecha si quieres que el timestamp se vea diferente
        // Por defecto, Jackson serializará el 'long scanTimestamp' como un número.
        // Si quieres un formato de fecha legible, tendrías que cambiar el tipo en NetworkReport
        // o usar un @JsonFormat en el getter de NetworkReport.
        // Ejemplo si scanTimestamp fuera Date:
        // this.objectMapper.setDateFormat(new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ"));
    }

    /**
     * Convierte un objeto NetworkReport a una cadena JSON.
     * @param report El NetworkReport a exportar.
     * @return Una cadena con el reporte en formato JSON, o un JSON de error si falla.
     */
    public String exportReportToJsonString(NetworkReport report) {
        if (report == null) {
            System.err.println("El reporte es nulo, no se puede convertir a JSON.");
            return "{\"error\":\"El reporte proporcionado es nulo\"}";
        }
        try {
            return objectMapper.writeValueAsString(report);
        } catch (Exception e) {
            System.err.println("Error al convertir el reporte a JSON: " + e.getMessage());
            // e.printStackTrace(); // Descomentar para depuración detallada
            return "{\"error\":\"No se pudo generar el JSON\", \"message\":\"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }
    }

    /**
     * Exporta un objeto NetworkReport a un archivo JSON.
     * @param report El NetworkReport a exportar.
     * @param filePath La ruta completa del archivo donde se guardará el JSON (ej. "reporte_red_local.json").
     */
    public void exportReportToFile(NetworkReport report, String filePath) {
        if (report == null) {
            System.err.println("El reporte es nulo, no se puede exportar a archivo.");
            return;
        }
        if (filePath == null || filePath.trim().isEmpty()) {
            System.err.println("La ruta del archivo es nula o vacía, no se puede exportar.");
            return;
        }

        try {
            File outputFile = new File(filePath);
            // Crear directorios padres si no existen
            File parentDir = outputFile.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                if (parentDir.mkdirs()) {
                    System.out.println("Directorios creados: " + parentDir.getAbsolutePath());
                } else {
                    System.err.println("No se pudieron crear los directorios: " + parentDir.getAbsolutePath());
                    // Considerar no continuar si no se pueden crear los directorios
                }
            }
            objectMapper.writeValue(outputFile, report);
            System.out.println("Reporte exportado exitosamente a: " + outputFile.getAbsolutePath());
        } catch (IOException e) {
            System.err.println("Error al escribir el reporte JSON al archivo '" + filePath + "': " + e.getMessage());
            // e.printStackTrace(); // Descomentar para depuración detallada
        } catch (Exception e) {
            System.err.println("Error inesperado al exportar el reporte al archivo '" + filePath + "': " + e.getMessage());
            // e.printStackTrace(); // Descomentar para depuración detallada
        }
    }
}
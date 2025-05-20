package com.miproyectored.scanner;

import com.miproyectored.model.Device;
// import com.miproyectored.util.NetworkUtils; // Descomentar si se usa getHostname como fallback

import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

public class NmapScanner {

    private String nmapPath;

    public NmapScanner(String nmapPath) {
        this.nmapPath = nmapPath;
        if (!isNmapAvailable(this.nmapPath)) {
            System.err.println("Nmap no parece ser ejecutable en la ruta especificada: " + this.nmapPath);
            // Considera lanzar una excepción aquí para manejo de errores más robusto
        }
    }

    public NmapScanner() {
        this.nmapPath = findNmapPath();
        if (this.nmapPath == null) {
            System.err.println("Nmap no encontrado en el PATH del sistema ni en ubicaciones comunes. " +
                               "Por favor, instala Nmap y asegúrate de que esté en el PATH, " +
                               "o proporciona la ruta explícitamente al constructor de NmapScanner.");
            // Considera lanzar una excepción
        }
    }

    private String findNmapPath() {
        String os = System.getProperty("os.name").toLowerCase();
        String command = "nmap";
        if (os.contains("win")) {
            // Intentar con "nmap" (si está en PATH)
            if (isNmapAvailable(command)) return command;
            // Comprobar rutas comunes en Windows
            String commonPathProgramFiles = "C:\\Program Files\\Nmap\\nmap.exe";
            if (new java.io.File(commonPathProgramFiles).exists() && isNmapAvailable(commonPathProgramFiles)) return commonPathProgramFiles;
            String commonPathProgramFilesX86 = "C:\\Program Files (x86)\\Nmap\\nmap.exe";
            if (new java.io.File(commonPathProgramFilesX86).exists() && isNmapAvailable(commonPathProgramFilesX86)) return commonPathProgramFilesX86;
        } else { // Linux, macOS
            if (isNmapAvailable(command)) return command;
            // Podrías comprobar /usr/bin/nmap, /usr/local/bin/nmap, etc.
            String commonPathUsrBin = "/usr/bin/nmap";
            if (new java.io.File(commonPathUsrBin).exists() && isNmapAvailable(commonPathUsrBin)) return commonPathUsrBin;
            String commonPathUsrLocalBin = "/usr/local/bin/nmap";
            if (new java.io.File(commonPathUsrLocalBin).exists() && isNmapAvailable(commonPathUsrLocalBin)) return commonPathUsrLocalBin;
        }
        return null;
    }

    private boolean isNmapAvailable(String commandOrPath) {
        try {
            ProcessBuilder pb = new ProcessBuilder(commandOrPath, "-V"); // Nmap version check
            Process process = pb.start();
            // Consumir salida para evitar bloqueo del proceso
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                 BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                while (reader.readLine() != null || errorReader.readLine() != null) {
                    // Descartar salida
                }
            }
            process.waitFor();
            return process.exitValue() == 0;
        } catch (Exception e) {
            // System.err.println("Error verificando Nmap en '" + commandOrPath + "': " + e.getMessage());
            return false;
        }
    }

    public List<Device> scan(String target) {
        if (this.nmapPath == null) {
            System.err.println("Ruta de Nmap no configurada o Nmap no disponible. No se puede escanear.");
            return new ArrayList<>();
        }

        List<String> command = new ArrayList<>();
        command.add(nmapPath);
        // Opciones base de Nmap
        command.add("-sT");         // TCP Connect scan (no requiere privilegios especiales, más fiable que -sS sin ellos)
        command.add("-sV");         // Detección de versión de servicios
        command.add("-O");          // Intento de detección de OS (puede ser limitado sin privilegios)
        // command.add("--osscan-guess"); // Opción para ser más agresivo con la detección de OS si -O es muy pasivo

        // Opciones para mejorar velocidad y fiabilidad en algunos entornos:
        // command.add("-T4");      // Timing template: Aggressive. Usar con cuidado, puede ser ruidoso. T3 es default.
        command.add("-Pn");         // Tratar todos los hosts como online (saltar descubrimiento de host por ping).
                                    // Útil si los hosts bloquean pings, pero puede ralentizar si muchos IPs no responden.
        // command.add("--max-retries"); command.add("1"); // Reducir reintentos para escaneos más rápidos en redes fiables.
        // command.add("--host-timeout"); command.add("5m"); // Tiempo máximo por host

        command.add("-oX");
        command.add("-");
        command.add(target);

        System.out.println("Ejecutando Nmap: " + String.join(" ", command));
        List<Device> devices = new ArrayList<>();
        long timeoutMinutes = 15; // Establece un tiempo de espera máximo para Nmap (ej. 15 minutos)

        try {
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            Process process = processBuilder.start();

            StringBuilder xmlOutput = new StringBuilder();
            StringBuilder errorOutput = new StringBuilder();

            // Hilo para leer la salida estándar (stdout) de Nmap
            Thread outputThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        xmlOutput.append(line).append(System.lineSeparator());
                    }
                } catch (Exception e) {
                    // Manejar o registrar la excepción si es necesario
                    // System.err.println("Error leyendo stdout de Nmap: " + e.getMessage());
                }
            });

            // Hilo para leer la salida de error (stderr) de Nmap
            Thread errorThread = new Thread(() -> {
                try (BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                    String line;
                    while ((line = errorReader.readLine()) != null) {
                        errorOutput.append(line).append(System.lineSeparator());
                    }
                } catch (Exception e) {
                    // Manejar o registrar la excepción si es necesario
                    // System.err.println("Error leyendo stderr de Nmap: " + e.getMessage());
                }
            });

            outputThread.start();
            errorThread.start();

            // Esperar a que el proceso Nmap termine, con un tiempo de espera
            boolean finishedInTime = process.waitFor(timeoutMinutes, java.util.concurrent.TimeUnit.MINUTES);
            
            // Asegurarse de que los hilos de lectura también terminen
            // Esperar un poco más por si queda algo en los buffers, especialmente si Nmap terminó rápido o por timeout
            outputThread.join(5000); 
            errorThread.join(5000);

            if (finishedInTime) {
                int exitCode = process.exitValue();
                if (exitCode == 0) {
                    System.out.println("Nmap ejecutado correctamente. Parseando salida XML...");
                    // System.out.println("XML Output:\n" + xmlOutput.toString()); // Para depuración
                    devices = parseNmapXmlOutputWithJackson(xmlOutput.toString());
                } else {
                    System.err.println("Nmap terminó con errores. Código de salida: " + exitCode);
                    if (errorOutput.length() > 0) {
                        System.err.println("Errores de Nmap:\n" + errorOutput.toString());
                    }
                    if (xmlOutput.length() > 0 && xmlOutput.toString().contains("Failed to open Normal Output File")) {
                        System.err.println("Nmap puede haber tenido problemas con la salida -oX -. Verifica la instalación y permisos de Nmap.");
                    }
                }
            } else {
                // Nmap excedió el tiempo de espera
                System.err.println("Nmap excedió el tiempo de espera de " + timeoutMinutes + " minutos.");
                process.destroyForcibly(); // Intentar terminar el proceso Nmap
                if (errorOutput.length() > 0) {
                    System.err.println("Posibles errores de Nmap (antes del timeout):\n" + errorOutput.toString());
                }
                 if (xmlOutput.length() > 0) { // También mostrar la salida XML parcial si hubo timeout
                    System.err.println("Salida XML parcial de Nmap (antes del timeout):\n" + xmlOutput.toString());
                }
            }

        } catch (InterruptedException e) {
            System.err.println("El escaneo de Nmap fue interrumpido: " + e.getMessage());
            Thread.currentThread().interrupt(); // Restaurar el estado de interrupción
        } catch (Exception e) {
            System.err.println("Error ejecutando Nmap o procesando su salida: " + e.getMessage());
            // e.printStackTrace(); // Para depuración
        }
        return devices;
    }

    private List<Device> parseNmapXmlOutputWithJackson(String xmlData) {
        List<Device> devices = new ArrayList<>();
        if (xmlData == null || xmlData.trim().isEmpty()) {
            System.err.println("Datos XML de Nmap vacíos o nulos. No se puede parsear.");
            return devices;
        }

        try {
            XmlMapper xmlMapper = new XmlMapper();
            // Deshabilitar características que podrían causar problemas con XML complejo o inesperado
            // xmlMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false); // Ya cubierto por @JsonIgnoreProperties
            NmapRun nmapRun = xmlMapper.readValue(xmlData, NmapRun.class);

            if (nmapRun != null && nmapRun.hosts != null) {
                for (NmapHost nmapHost : nmapRun.hosts) {
                    if (nmapHost.status == null || !"up".equalsIgnoreCase(nmapHost.status.state)) {
                        continue; // Solo procesar hosts que están "up"
                    }

                    String ipAddress = null;
                    String macAddress = null;
                    String manufacturer = null;

                    if (nmapHost.addresses != null) {
                        for (NmapAddress addr : nmapHost.addresses) {
                            if ("ipv4".equalsIgnoreCase(addr.addrtype)) {
                                ipAddress = addr.addr;
                            } else if ("mac".equalsIgnoreCase(addr.addrtype)) {
                                macAddress = addr.addr;
                                manufacturer = addr.vendor;
                            }
                        }
                    }

                    if (ipAddress == null) {
                        System.err.println("Host en XML de Nmap sin dirección IPv4. Saltando host.");
                        continue; 
                    }

                    Device device = new Device(ipAddress);
                    if (macAddress != null) {
                        device.setMac(macAddress.toUpperCase());
                        if (manufacturer != null && !manufacturer.isEmpty()) {
                            device.setManufacturer(manufacturer);
                        }
                    }

                    if (nmapHost.hostnames != null && nmapHost.hostnames.hostnames != null) {
                        for (NmapHostname hn : nmapHost.hostnames.hostnames) {
                            if ("PTR".equalsIgnoreCase(hn.type) || "user".equalsIgnoreCase(hn.type) || hn.type == null) { 
                                // "user" es a veces el tipo para nombres de host resueltos, PTR es el más común.
                                device.setHostname(hn.name);
                                break; 
                            }
                        }
                    }
                    
                    if (nmapHost.ports != null && nmapHost.ports.ports != null) {
                        List<Integer> openPorts = new ArrayList<>();
                        Map<Integer, String> services = new HashMap<>();
                        for (NmapPort nmapPort : nmapHost.ports.ports) {
                            if (nmapPort.state != null && "open".equalsIgnoreCase(nmapPort.state.state)) {
                                try {
                                    // La siguiente línea convierte el 'portid' (String) a 'int'.
                                    // Esta es la forma correcta de hacerlo.
                                    int portId = Integer.parseInt(nmapPort.portid); 
                                    openPorts.add(portId);
                                    if (nmapPort.service != null) {
                                        StringBuilder serviceDesc = new StringBuilder(nmapPort.service.name != null ? nmapPort.service.name : "unknown");
                                        if (nmapPort.service.product != null) serviceDesc.append(" (").append(nmapPort.service.product);
                                        if (nmapPort.service.version != null) serviceDesc.append(" ").append(nmapPort.service.version);
                                        if (nmapPort.service.extrainfo != null) serviceDesc.append(" ").append(nmapPort.service.extrainfo);
                                        if (nmapPort.service.product != null) serviceDesc.append(")");
                                        services.put(portId, serviceDesc.toString().trim());
                                    } else {
                                        services.put(portId, "Unknown service");
                                    }
                                } catch (NumberFormatException e) {
                                    System.err.println("Error parseando portid: " + nmapPort.portid + " para IP: " + ipAddress);
                                }
                            }
                        }
                        device.setOpenPorts(openPorts);
                        device.setServices(services);
                    }

                    if (nmapHost.os != null && nmapHost.os.osmatches != null && !nmapHost.os.osmatches.isEmpty()) {
                        NmapOsMatch bestOsMatch = nmapHost.os.osmatches.get(0); // Tomar la primera por defecto
                        // Opcionalmente, buscar la de mayor "accuracy" si hay varias
                        // for (NmapOsMatch match : nmapHost.os.osmatches) {
                        //    if (Integer.parseInt(match.accuracy) > Integer.parseInt(bestOsMatch.accuracy)) {
                        //        bestOsMatch = match;
                        //    }
                        // }
                        device.setOs(bestOsMatch.name + " (Accuracy: " + bestOsMatch.accuracy + "%)");
                    }
                    
                    devices.add(device);
                    // System.out.println("Dispositivo parseado con Jackson: " + device.getIp()); // Para depuración
                }
            } else {
                 System.out.println("NmapRun o nmapRun.hosts es nulo después del parseo XML.");
            }
        } catch (Exception e) {
            System.err.println("Error crítico parseando XML de Nmap con Jackson: " + e.getMessage());
            // e.printStackTrace(); // Descomentar para traza completa durante el desarrollo
            // Podrías considerar guardar el XML problemático para análisis
            // System.err.println("XML problemático:\n" + xmlData);
        }
        return devices;
    }

    // --- Clases POJO para parsear XML de Nmap con Jackson ---
    @JsonIgnoreProperties(ignoreUnknown = true)
    static class NmapRun {
        @JacksonXmlElementWrapper(useWrapping = false)
        @JacksonXmlProperty(localName = "host")
        public List<NmapHost> hosts;

        @JacksonXmlProperty(isAttribute = true)
        public String version; // Para capturar la versión de Nmap del reporte
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class NmapHost {
        @JacksonXmlProperty(localName = "status")
        public NmapStatus status;

        @JacksonXmlElementWrapper(useWrapping = false)
        @JacksonXmlProperty(localName = "address")
        public List<NmapAddress> addresses;

        @JacksonXmlProperty(localName = "hostnames")
        public NmapHostnames hostnames;

        @JacksonXmlProperty(localName = "ports")
        public NmapPorts ports;
        
        @JacksonXmlProperty(localName = "os")
        public NmapOs os;

        @JacksonXmlProperty(isAttribute = true)
        public String starttime;
        @JacksonXmlProperty(isAttribute = true)
        public String endtime;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class NmapStatus {
        @JacksonXmlProperty(isAttribute = true)
        public String state;
        @JacksonXmlProperty(isAttribute = true)
        public String reason;
        @JacksonXmlProperty(isAttribute = true)
        public String reason_ttl;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class NmapAddress {
        @JacksonXmlProperty(isAttribute = true)
        public String addr;
        @JacksonXmlProperty(isAttribute = true)
        public String addrtype;
        @JacksonXmlProperty(isAttribute = true)
        public String vendor;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class NmapHostnames {
        @JacksonXmlElementWrapper(useWrapping = false) 
        @JacksonXmlProperty(localName = "hostname")
        public List<NmapHostname> hostnames;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class NmapHostname {
        @JacksonXmlProperty(isAttribute = true)
        public String name;
        @JacksonXmlProperty(isAttribute = true)
        public String type; // e.g., "PTR", "user"
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class NmapPorts {
        @JacksonXmlElementWrapper(useWrapping = false)
        @JacksonXmlProperty(localName = "port")
        public List<NmapPort> ports;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class NmapPort {
        @JacksonXmlProperty(isAttribute = true)
        public String protocol; // "tcp", "udp"
        @JacksonXmlProperty(isAttribute = true)
        public String portid;

        @JacksonXmlProperty(localName = "state")
        public NmapPortState state;
        @JacksonXmlProperty(localName = "service")
        public NmapService service;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class NmapPortState {
        @JacksonXmlProperty(isAttribute = true)
        public String state; // "open", "closed", "filtered"
        @JacksonXmlProperty(isAttribute = true)
        public String reason;
        @JacksonXmlProperty(isAttribute = true)
        public String reason_ttl;
        @JacksonXmlProperty(isAttribute = true)
        public String reason_ip;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class NmapService {
        @JacksonXmlProperty(isAttribute = true)
        public String name;
        @JacksonXmlProperty(isAttribute = true)
        public String product;
        @JacksonXmlProperty(isAttribute = true)
        public String version;
        @JacksonXmlProperty(isAttribute = true)
        public String extrainfo;
        @JacksonXmlProperty(isAttribute = true)
        public String ostype; 
        @JacksonXmlProperty(isAttribute = true)
        public String method; // "probed", "table"
        @JacksonXmlProperty(isAttribute = true)
        public String conf; // Nivel de confianza (1-10)
    }
    
    @JsonIgnoreProperties(ignoreUnknown = true)
    static class NmapOs {
        @JacksonXmlElementWrapper(localName = "osmatch", useWrapping = false)
        @JacksonXmlProperty(localName = "osmatch")
        public List<NmapOsMatch> osmatches;
        
        @JacksonXmlElementWrapper(localName = "portused", useWrapping = false)
        @JacksonXmlProperty(localName = "portused")
        public List<NmapPortUsed> portused; 
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class NmapPortUsed {
        @JacksonXmlProperty(isAttribute = true)
        public String state;
        @JacksonXmlProperty(isAttribute = true)
        public String proto;
        @JacksonXmlProperty(isAttribute = true)
        public String portid;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class NmapOsMatch {
        @JacksonXmlProperty(isAttribute = true)
        public String name;
        @JacksonXmlProperty(isAttribute = true)
        public String accuracy;
        @JacksonXmlProperty(isAttribute = true)
        public int line; // Corresponde al atributo 'line' en el XML de Nmap para <osmatch>

        @JacksonXmlElementWrapper(localName = "osclass", useWrapping = false)
        @JacksonXmlProperty(localName = "osclass")
        public List<NmapOsClass> osclasses;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class NmapOsClass {
        @JacksonXmlProperty(isAttribute = true)
        public String type;     // e.g., "general purpose"
        @JacksonXmlProperty(isAttribute = true)
        public String vendor;   // e.g., "Linux"
        @JacksonXmlProperty(isAttribute = true)
        public String osfamily; // e.g., "Linux"
        @JacksonXmlProperty(isAttribute = true)
        public String osgen;    // e.g., "3.X"
        @JacksonXmlProperty(isAttribute = true)
        public String accuracy; // e.g., "100"
        // Si necesitas parsear <cpe> dentro de <osclass>:
        // @JacksonXmlElementWrapper(useWrapping = false)
        // @JacksonXmlProperty(localName = "cpe")
        // public List<String> cpe; // O String si solo esperas uno
    }
}
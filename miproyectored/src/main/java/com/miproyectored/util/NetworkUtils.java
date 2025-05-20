package com.miproyectored.util;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

public class NetworkUtils {

    /**
     * Detecta las redes locales (formato CIDR, ej. "192.168.1.0/24") a las que la máquina está conectada.
     * Intenta excluir interfaces de loopback y virtuales.
     * @return Una lista de strings, donde cada string es una dirección de red en notación CIDR.
     */
    public static List<String> detectLocalNetworks() {
        List<String> networks = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            for (NetworkInterface ni : Collections.list(interfaces)) {
                // Filtramos interfaces que no están activas, son de loopback o virtuales.
                if (!ni.isUp() || ni.isLoopback() || ni.isVirtual()) {
                    continue;
                }

                // Recorremos todas las direcciones asignadas a esta interfaz de red
                for (InterfaceAddress interfaceAddress : ni.getInterfaceAddresses()) {
                    InetAddress ipAddress = interfaceAddress.getAddress();

                    // Nos enfocamos en direcciones IPv4
                    if (ipAddress instanceof Inet4Address) {
                        short prefixLength = interfaceAddress.getNetworkPrefixLength();
                        // Validamos que el prefijo sea razonable para IPv4
                        if (prefixLength > 0 && prefixLength <= 32) {
                            String networkAddress = calculateNetworkAddress(ipAddress.getHostAddress(), prefixLength);
                            if (networkAddress != null) {
                                String networkCIDR = networkAddress + "/" + prefixLength;
                                if (!networks.contains(networkCIDR)) { // Evitar duplicados
                                    networks.add(networkCIDR);
                                    System.out.println("Interfaz: " + ni.getDisplayName() + " -> Red detectada: " + networkCIDR);
                                }
                            }
                        }
                    }
                }
            }
        } catch (SocketException e) {
            System.err.println("Error al acceder a las interfaces de red: " + e.getMessage());
            // Podrías devolver una lista vacía o una red por defecto aquí si lo deseas
        }
        return networks;
    }

    /**
     * Calcula la dirección de red base a partir de una dirección IP y la longitud de su prefijo de red (máscara).
     * Por ejemplo, para IP "192.168.1.100" y prefijo 24, devuelve "192.168.1.0".
     * @param ip La dirección IP en formato string (ej. "192.168.1.100").
     * @param prefixLength La longitud del prefijo de red (ej. 24 para una máscara /24 o 255.255.255.0).
     * @return La dirección de red calculada como un String, o null si hay un error.
     */
    public static String calculateNetworkAddress(String ip, short prefixLength) {
        try {
            InetAddress inetAddress = InetAddress.getByName(ip);
            byte[] ipBytes = inetAddress.getAddress(); // Obtiene la IP como un array de bytes

            // Aseguramos que es una IPv4 (4 bytes)
            if (ipBytes.length != 4) {
                System.err.println("calculateNetworkAddress solo soporta IPv4. IP recibida: " + ip);
                return null;
            }

            // Convertimos los 4 bytes de la IP a un entero de 32 bits
            int ipInt = ((ipBytes[0] & 0xFF) << 24) |
                        ((ipBytes[1] & 0xFF) << 16) |
                        ((ipBytes[2] & 0xFF) << 8)  |
                        (ipBytes[3] & 0xFF);

            // Creamos la máscara de red como un entero.
            // -1 en binario son todos los bits a 1.
            // Desplazamos a la izquierda (32 - prefixLength) bits. Esto pone a 0 los bits del host.
            // Ejemplo: prefixLength = 24. (32-24) = 8.  -1 << 8  (11111111... << 8)
            // Esto resulta en una máscara con 'prefixLength' bits a 1 seguidos de (32-prefixLength) bits a 0.
            // ej. /24 -> 11111111.11111111.11111111.00000000
            int mask = -1 << (32 - prefixLength);

            // Aplicamos la máscara a la IP usando un AND bit a bit.
            // Esto pone a cero los bits de la porción de host de la IP, revelando la dirección de red.
            int networkInt = ipInt & mask;

            // Convertimos el entero de la dirección de red de nuevo a un array de 4 bytes
            byte[] networkBytes = new byte[] {
                (byte) (networkInt >>> 24),          // Extrae el primer byte (el más significativo)
                (byte) ((networkInt >>> 16) & 0xFF), // Extrae el segundo byte
                (byte) ((networkInt >>> 8) & 0xFF),  // Extrae el tercer byte
                (byte) (networkInt & 0xFF)           // Extrae el cuarto byte (el menos significativo)
            };

            // Convertimos el array de bytes de la dirección de red a un String (ej. "192.168.1.0")
            return InetAddress.getByAddress(networkBytes).getHostAddress();

        } catch (UnknownHostException e) {
            System.err.println("Error al procesar la dirección IP '" + ip + "': " + e.getMessage());
            return null;
        }
    }

    /**
     * Intenta resolver el nombre de host para una dirección IP dada.
     * @param ipAddress La dirección IP a resolver.
     * @return El nombre de host si se resuelve, o la misma dirección IP si no.
     */
    public static String getHostname(String ipAddress) {
        try {
            InetAddress addr = InetAddress.getByName(ipAddress);
            // getHostName() intentará una búsqueda DNS inversa.
            // Si falla o toma mucho tiempo, getCanonicalHostName() puede ser una alternativa,
            // pero también puede ser lento.
            String hostname = addr.getHostName();
            if (hostname.equals(ipAddress)) {
                // Si getHostName() devuelve la IP, es que no pudo resolver.
                // Podríamos intentar con getCanonicalHostName() como fallback,
                // pero a menudo tiene el mismo resultado o es más lento.
                // String canonicalHostname = addr.getCanonicalHostName();
                // return canonicalHostname;
                return ipAddress; // No se pudo resolver, devolvemos la IP
            }
            return hostname;
        } catch (UnknownHostException e) {
            // System.err.println("No se pudo resolver el hostname para: " + ipAddress);
            return ipAddress; // Devuelve la IP si no se puede resolver
        }
    }
}
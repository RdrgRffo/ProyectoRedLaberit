package com.miproyectored.model;

import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.HashMap;

public class Device {
    private String ip;                     // Dirección IP del dispositivo
    private String hostname;               // Nombre de host (si se puede resolver)
    private List<Integer> openPorts;       // Lista de puertos TCP abiertos
    private Map<Integer, String> services; // Mapa de puerto -> descripción del servicio
    private String mac;                    // Dirección MAC (si se puede obtener)
    private String manufacturer;           // Fabricante (basado en la MAC, opcional)
    private String os;                     // Sistema operativo detectado (opcional)
    private String riskLevel;              // Nivel de riesgo ("low", "medium", "high")

    // Constructor
    public Device(String ip) {
        this.ip = ip;
        this.openPorts = new ArrayList<>(); // Inicializa la lista de puertos vacía
        this.services = new HashMap<>();    // Inicializa el mapa de servicios vacío
        // Otros campos se pueden inicializar a null o valores por defecto si es necesario
        this.hostname = ip; // Por defecto, el hostname es la IP hasta que se resuelva
    }

    // Getters (para obtener los valores de los atributos)
    public String getIp() {
        return ip;
    }

    public String getHostname() {
        return hostname;
    }

    public List<Integer> getOpenPorts() {
        return openPorts;
    }

    public Map<Integer, String> getServices() {
        return services;
    }

    public String getMac() {
        return mac;
    }

    public String getManufacturer() {
        return manufacturer;
    }

    public String getOs() {
        return os;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    // Setters (para establecer o modificar los valores de los atributos)
    public void setIp(String ip) {
        this.ip = ip;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public void setOpenPorts(List<Integer> openPorts) {
        this.openPorts = openPorts;
    }

    public void setServices(Map<Integer, String> services) {
        this.services = services;
    }

    public void setMac(String mac) {
        this.mac = mac;
    }

    public void setManufacturer(String manufacturer) {
        this.manufacturer = manufacturer;
    }

    public void setOs(String os) {
        this.os = os;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    // Método toString (útil para depuración, para imprimir el objeto de forma legible)
    @Override
    public String toString() {
        return "Device{" +
               "ip='" + ip + '\'' +
               ", hostname='" + hostname + '\'' +
               ", openPorts=" + openPorts +
               ", services=" + services +
               ", mac='" + mac + '\'' +
               ", os='" + os + '\'' +
               ", riskLevel='" + riskLevel + '\'' +
               '}';
    }
}
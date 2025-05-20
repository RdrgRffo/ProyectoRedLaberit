package com.miproyectored.model;

import java.util.ArrayList;
import java.util.List;

public class NetworkReport {
    private long scanTimestamp;
    private String scannedNetworkTarget; // Campo para el objetivo del escaneo
    private List<Device> devices;
    private String scanEngineInfo; // Opcional, para información del motor de escaneo

    public NetworkReport() {
        this.scanTimestamp = System.currentTimeMillis();
        this.devices = new ArrayList<>();
    }

    public void addDevice(Device device) {
        this.devices.add(device);
    }

    public List<Device> getDevices() {
        return devices;
    }

    public int getDeviceCount() {
        return devices.size();
    }

    public long getScanTimestamp() { // Getter para scanTimestamp
        return scanTimestamp;
    }

    public String getScannedNetworkTarget() { // Getter para scannedNetworkTarget
        return scannedNetworkTarget;
    }

    public void setScannedNetworkTarget(String scannedNetworkTarget) { // Setter para scannedNetworkTarget
        this.scannedNetworkTarget = scannedNetworkTarget;
    }

    public String getScanEngineInfo() {
        return scanEngineInfo;
    }

    public void setScanEngineInfo(String scanEngineInfo) {
        this.scanEngineInfo = scanEngineInfo;
    }
}
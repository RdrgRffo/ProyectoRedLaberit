package com.miproyectored.ssh;

import com.jcraft.jsch.*;
import java.io.*;
import java.util.HashMap;
import java.util.Map;

public class SSHHandler {
    private static final int SSH_PORT = 22;
    private static final int TIMEOUT = 10000;

    public static class SSHResult {
        private String hostname;
        private Map<String, String> systemInfo;

        public SSHResult(String hostname) {
            this.hostname = hostname;
            this.systemInfo = new HashMap<>();
        }

        public void addInfo(String key, String value) {
            systemInfo.put(key, value);
        }

        public String getHostname() { return hostname; }
        public Map<String, String> getSystemInfo() { return systemInfo; }
    }

    public static SSHResult getSystemInfo(String host, String username, String password) {
        SSHResult result = new SSHResult(host);
        Session session = null;

        try {
            JSch jsch = new JSch();
            session = jsch.getSession(username, host, SSH_PORT);
            session.setPassword(password);

            // No verificar la clave del host
            java.util.Properties config = new java.util.Properties();
            config.put("StrictHostKeyChecking", "no");
            session.setConfig(config);

            session.connect(TIMEOUT);

            // Comandos para obtener información del sistema
            Map<String, String> commands = new HashMap<>();
            commands.put("OS", "cat /etc/os-release | grep PRETTY_NAME");
            commands.put("Kernel", "uname -r");
            commands.put("Uptime", "uptime");
            commands.put("CPU", "lscpu | grep 'Model name'");
            commands.put("Memory", "free -h");
            commands.put("Disk", "df -h");

            for (Map.Entry<String, String> entry : commands.entrySet()) {
                String output = executeCommand(session, entry.getValue());
                result.addInfo(entry.getKey(), output.trim());
            }

        } catch (JSchException e) {
            System.err.println("Error de conexión SSH: " + e.getMessage());
        } finally {
            if (session != null && session.isConnected()) {
                session.disconnect();
            }
        }

        return result;
    }

    private static String executeCommand(Session session, String command) {
        StringBuilder output = new StringBuilder();
        try {
            Channel channel = session.openChannel("exec");
            ((ChannelExec) channel).setCommand(command);

            InputStream in = channel.getInputStream();
            channel.connect();

            byte[] tmp = new byte[1024];
            while (true) {
                while (in.available() > 0) {
                    int i = in.read(tmp, 0, 1024);
                    if (i < 0) break;
                    output.append(new String(tmp, 0, i));
                }
                if (channel.isClosed()) {
                    break;
                }
                Thread.sleep(100);
            }
            channel.disconnect();

        } catch (Exception e) {
            output.append("Error ejecutando comando: ").append(e.getMessage());
        }
        return output.toString();
    }
}
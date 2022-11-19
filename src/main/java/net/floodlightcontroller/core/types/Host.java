package net.floodlightcontroller.core.types;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.firewall.FirewallConectadosSerializer;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.OFPort;


@JsonSerialize(using= FirewallConectadosSerializer.class)
public class Host {
    private String DPID_SW;
    private String MAC;
    private int portSW;
    private String IP;


    public Host(String SW, String MAC, int portSW, String IP) {
        this.DPID_SW = SW;
        this.MAC = MAC;
        this.portSW = portSW;
        this.IP = IP;
    }

    public Host() {
    }

    public String getSW() {
        return DPID_SW;
    }

    public void setSW(String SW) {
        this.DPID_SW = SW;
    }

    public String getMAC() {
        return MAC;
    }

    public void setMAC(String MAC) {
        this.MAC = MAC;
    }

    public int getPortSW() {
        return portSW;
    }

    public void setPortSW(int portSW) {
        this.portSW = portSW;
    }

    public String getIP() {
        return IP;
    }

    public void setIP(String IP) {
        this.IP = IP;
    }
}

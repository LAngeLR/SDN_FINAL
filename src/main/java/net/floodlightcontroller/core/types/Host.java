package net.floodlightcontroller.core.types;

import net.floodlightcontroller.core.IOFSwitch;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.OFPort;

public class Host {
    private String DPID_SW;
    private Long MAC;
    private int portSW;
    private IPv4Address IP;


    public Host(String SW, Long MAC, int portSW, IPv4Address IP) {
        this.DPID_SW = SW;
        this.MAC = MAC;
        this.portSW = portSW;
        this.IP = IP;
    }

    public String getSW() {
        return DPID_SW;
    }

    public void setSW(String SW) {
        this.DPID_SW = SW;
    }

    public Long getMAC() {
        return MAC;
    }

    public void setMAC(Long MAC) {
        this.MAC = MAC;
    }

    public int getPortSW() {
        return portSW;
    }

    public void setPortSW(int portSW) {
        this.portSW = portSW;
    }

    public IPv4Address getIP() {
        return IP;
    }

    public void setIP(IPv4Address IP) {
        this.IP = IP;
    }
}

package net.floodlightcontroller.AAM;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.types.Host;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class AAM implements IOFMessageListener, IFloodlightModule {
    protected static Logger logger;
    protected IFloodlightProviderService floodlightProvider;
    protected HashMap<String,ArrayList<Host>> sesiones;
    protected String MACWebServer;
    protected IPv4Address IPv4WebServer;
    protected int PortWebServer = 8080;

    @Override
    public String getName() {
        return "AAM";
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return false;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
        return l;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        Map<Class<? extends IFloodlightService>, IFloodlightService> m = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
        return m;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        logger = LoggerFactory.getLogger(AAM.class);
        sesiones = new HashMap<>();

    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        switch (msg.getType()){
            case PACKET_IN:
                boolean estaEnSesion = false;

                Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
                IPv4 ip = (IPv4) eth.getPayload();

                //Detecto la MAC
                String sourceMAC= eth.getSourceMACAddress().toString();

                //Detecto el SW
                String DPID_SW = sw.getId().toString();

                //Detecto el OFPort -->PREGUNTAR
                int portSW = 3;

                //Detecto la IP
                IPv4Address sourceIP = ip.getSourceAddress();

                //Creo un host
                Host host = new Host(DPID_SW,sourceMAC,portSW,sourceIP);

                logger.info("--------------------------------------------------------------------------------------------------------------");
                logger.info("Se ha detectado un host conectado: MAC: "+sourceMAC+" /DPID_SW: "+DPID_SW+" /port_SW: "+portSW+"/ IP:"+sourceIP);


                if(!ip.equals(IPv4WebServer) && !sourceMAC.equals(MACWebServer)){
                    if(!sesiones.isEmpty()){
                        for(ArrayList<Host> sesiones : sesiones.values()){
                            if(sesiones.contains(host)){
                                estaEnSesion = true;
                                break;
                            }
                        }
                    }
                }


                if(estaEnSesion){
                    //Esta en sesion el usuario

                }else{
                    //significa usuario nuevo o cerro sesion anteriomente por lo que no tiene una sesion activa -> no esta autenticado
                    if(eth.getEtherType().equals(EthType.IPv4)){
                        if(ip.getProtocol().equals(IpProtocol.TCP)){
                            TCP tcp = (TCP) ip.getPayload();

                            //HOST -----> SYN----> SERVER
                            if(tcp.getFlags() == (short) 0x02){
                                //Detecto el destination Port
                                int destPort = tcp.getDestinationPort().getPort(); //8080

                                //Detecto la MAC
                                Long destMAC = eth.getDestinationMACAddress().getLong();

                                //Detecto la IP
                                IPv4Address destIP = ip.getDestinationAddress();

                                if(destPort==PortWebServer && destMAC.equals(MACWebServer) && destIP.equals(IPv4WebServer)){

                                    //Creo PACKET-OUT


                                }else{
                                    logger.info("El puerto no es 8080 o la MAC o la IP no es la del servidor");
                                }

                            }

                            //Falta ver los casos de ACK y SYN+ACK




                        }else{
                            logger.info("Trafico no aceptado 2");
                        }
                    }else{
                        logger.info("Trafico no aceptado 1");
                    }

                }

                //https://wiki.wireshark.org/SampleCaptures#hypertext-transport-protocol-http
                //https://www.firewall.cx/networking-topics/protocols/tcp/136-tcp-flag-options.html

                break;
            default:
                logger.info("Se ha detectado un mensaje que no es PACKET_IN");
                break;
        }

        return Command.CONTINUE;
    }
}

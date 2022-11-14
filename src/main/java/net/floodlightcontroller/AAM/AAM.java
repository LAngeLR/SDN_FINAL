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
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.util.OFMessageUtils;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class AAM implements IOFMessageListener, IFloodlightModule {
    protected static Logger logger;
    protected IFloodlightProviderService floodlightProvider;
    protected HashMap<String,ArrayList<Host>> sesiones;

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
                Long sourceMAC= eth.getSourceMACAddress().getLong();

                //Detecto el SW
                String DPID_SW = sw.getId().toString();

                //Detecto el OFPort
                int portSW = 3;

                //Detecto la IP
                IPv4Address sourceIP = ip.getSourceAddress();

                //Creo un host
                Host host = new Host(DPID_SW,sourceMAC,portSW,sourceIP);

                logger.info("Se ha detectado un host conectado: MAC: "+sourceMAC+" /DPID_SW: "+DPID_SW+" /port_SW: "+portSW+"/ IP:"+sourceIP);

                //Collection<ArrayList<Host>> hosts = sesiones.values();
                for(ArrayList<Host> hostsHelper : sesiones.values()){
                    if(hostsHelper.contains(host)){
                        estaEnSesion = true;
                        break;
                    }
                }

                if(estaEnSesion){
                    //Esta en sesion el usuario

                }else{
                    //significa usuario nuevo o cerro sesion anteriomente por que no tiene una sesion activa
                    //no esta autenticado
	                //lee trafico
                    //if web server:
                    // else:
		            //no responde - drop

                }


                break;
            default:
                logger.info("Se ha detectado un mensaje que no es PACKET_IN");
                break;
        }

        return Command.CONTINUE;
    }
}

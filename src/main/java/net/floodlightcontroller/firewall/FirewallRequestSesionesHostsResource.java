package net.floodlightcontroller.firewall;

import net.floodlightcontroller.core.types.Host;
import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;

public class FirewallRequestSesionesHostsResource extends ServerResource {
    protected static Logger logger = LoggerFactory.getLogger(FirewallRequestLogOffWebServerResource.class);

    @Get
    public String listaSesiones() {
        IFirewallService firewallService = (IFirewallService)getContext().getAttributes().get(IFirewallService.class.getCanonicalName());

        HashMap<String, ArrayList<Host>> SS = firewallService.getSesiones();

        Set<String> arregloDeUsernames = SS.keySet();

        String mensajeFinal = "[";

        for(String username : arregloDeUsernames){
            ArrayList<Host> listita = SS.get(username);

            mensajeFinal = mensajeFinal + " \""+ username + "\":    [";

            if(listita.size() != 0){
                for(Host h : listita){
                    String IP = h.getIP();
                    String MAC = h.getMAC();
                    int port = h.getPortSW();
                    String DPID = h.getSW();

                    mensajeFinal = mensajeFinal + "{\n";
                    mensajeFinal =  mensajeFinal+"        "+"\"MAC\": \""+MAC+ "\",\n";
                    mensajeFinal = mensajeFinal+"        "+"\"IP\": \"" + IP+ "\",\n";
                    mensajeFinal = mensajeFinal+"        "+" \"Port\": \""+ port+ "\",\n";
                    mensajeFinal = mensajeFinal+"        "+" \"DPID\": \""+ DPID+ "\"\n";

                    mensajeFinal = mensajeFinal + "}\n";
                    mensajeFinal = mensajeFinal + "\n";
                }

            }

            mensajeFinal = mensajeFinal + " ]\n   ";

        }

        mensajeFinal = mensajeFinal + "]";

        return mensajeFinal;

    }


}

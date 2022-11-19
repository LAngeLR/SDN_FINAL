package net.floodlightcontroller.firewall;

import net.floodlightcontroller.core.web.ControllerSwitchesResource;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;
import net.floodlightcontroller.staticflowentry.StaticFlowEntries;
import net.floodlightcontroller.staticflowentry.StaticFlowEntryPusher;
import net.floodlightcontroller.staticflowentry.web.ListStaticFlowEntriesResource;
import net.floodlightcontroller.staticflowentry.web.OFFlowModMap;
import net.floodlightcontroller.storage.IStorageSourceService;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.types.DatapathId;
import org.restlet.data.Status;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class FirewallRequestWebServerResource extends ServerResource {
    protected static Logger logger = LoggerFactory.getLogger(FirewallRequestWebServerResource.class);

    @Post
    public String autenticado() {
        IFirewallService firewallService = (IFirewallService)getContext().getAttributes().get(IFirewallService.class.getCanonicalName());

        String username = (String) getRequestAttributes().get("username");
        String IP_user  = (String) getRequestAttributes().get("IP");

        logger.info("SE HIZO UN REQUEST CON USERNAME : "+username + " / IP : "+IP_user);


        try {
            firewallService.agregarHostAutenticado(username,IP_user);
            return "{\"Status\" : \"Host autenticado actualizado con exito!\"}";
        } catch (Exception e){
            return "{\"Status\" : \"An exception has ocurred!\"}";
        }

    }


}

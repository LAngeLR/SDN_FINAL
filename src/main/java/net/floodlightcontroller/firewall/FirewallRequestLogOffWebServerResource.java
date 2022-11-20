package net.floodlightcontroller.firewall;

import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FirewallRequestLogOffWebServerResource  extends ServerResource {
    protected static Logger logger = LoggerFactory.getLogger(FirewallRequestLogOffWebServerResource.class);

    @Post
    public String logoff() {
        IFirewallService firewallService = (IFirewallService)getContext().getAttributes().get(IFirewallService.class.getCanonicalName());

        String username = (String) getRequestAttributes().get("username");
        String IP_user  = (String) getRequestAttributes().get("IP");

        logger.info("SE HIZO UN REQUEST PARA LOG-OFF CON USERNAME : "+username + " / IP : "+IP_user);


        try {
            firewallService.cerrarSesionHost(username,IP_user);
            return "{\"Status\" : \"Sesión cerrada del host con exito!\"}";
        } catch (Exception e){
            return "{\"Status\" : \"An exception has ocurred!\"}";
        }

    }

}

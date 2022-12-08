package net.floodlightcontroller.firewall;

import net.floodlightcontroller.core.types.Host;
import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;

import java.util.List;

public class FirewallR3ConectadosResource extends ServerResource {

    @Get("json")
    public List<Host> retrieve2(){
        IFirewallService pihr = (IFirewallService) getContext().getAttributes().get(IFirewallService.class.getCanonicalName());
        return pihr.getR3Conectados();
    }

}

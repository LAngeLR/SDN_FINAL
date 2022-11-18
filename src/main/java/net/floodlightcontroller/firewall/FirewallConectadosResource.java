package net.floodlightcontroller.firewall;

import net.floodlightcontroller.core.types.Host;

import java.util.List;

public class FirewallConectadosResource extends ServerResource{

    @Get("json")
    public List<Host> retrieve(){
        IFirewallService pihr = (IFirewallService) getContext().getAttributes().get(IFirewallService.class.getCanonicalName());
        return pihr.getBuffer();

    }
}

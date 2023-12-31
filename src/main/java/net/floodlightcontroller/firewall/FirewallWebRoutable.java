/**
 *    Copyright 2011, Big Switch Networks, Inc.
 *    Originally created by Amer Tahir
 *    
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may 
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at
 *    
 *         http://www.apache.org/licenses/LICENSE-2.0 
 *    
 *    Unless required by applicable law or agreed to in writing, software 
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 **/

package net.floodlightcontroller.firewall;

import net.floodlightcontroller.restserver.RestletRoutable;
import net.floodlightcontroller.staticflowentry.web.ListStaticFlowEntriesResource;
import org.restlet.Context;
import org.restlet.routing.Router;

public class FirewallWebRoutable implements RestletRoutable {
    /**
     * Create the Restlet router and bind to the proper resources.
     */
    @Override
    public Router getRestlet(Context context) {
        Router router = new Router(context);
        router.attach("/module/status/json",       FirewallStatusResource.class);
        router.attach("/module/enable/json",       FirewallEnableResource.class);
        router.attach("/module/disable/json",      FirewallDisableResource.class);
        router.attach("/module/subnet-mask/json",  FirewallSubnetMaskResource.class);
        router.attach("/module/storageRules/json", FirewallStorageRulesResource.class);
        router.attach("/R1/conectados/json",       FirewallConectadosResource.class);
        router.attach("/rules/json",               FirewallRulesResource.class);
        router.attach("/R1/autenticados/{username}/{IP}/json",      FirewallRequestWebServerResource.class);
        router.attach("/R1/logoff/{username}/{IP}/json",FirewallRequestLogOffWebServerResource.class);
        router.attach("/R1/sesiones/json",FirewallRequestSesionesHostsResource.class);
        router.attach("/R2/permisos/host/{username}/json",FirewallPermisosHostsResource.class);
        router.attach("/R2/permisos/actualizar/host/{username}/json",FirewallPermisosActualizarHostsResource.class);
        router.attach("/R3/conectados/json", FirewallR3ConectadosResource.class);
        return router;
    }

    /**
     * Set the base path for the Firewall
     */
    @Override
    public String basePath() {
        return "/wm/firewall";
    }
}

package eu.stenlund;

import java.security.Principal;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Set;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;

import io.quarkus.security.Authenticated;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.PermitAll;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

@Path("/countries")
@RequestScoped
public class CountryResource {

    private Set<Country> countries = Collections.newSetFromMap(Collections.synchronizedMap(new LinkedHashMap<>()));
	private static final Logger log = Logger.getLogger("CountryResource");

    @Inject
    public SecurityIdentity securityIdentity;

    @Inject public JsonWebToken jwt;

    public CountryResource() {
        countries.add(new Country("Sweden", "Konungariket Sverige"));
        countries.add(new Country("Norge", "Konugariket Norge"));
    }

    @Authenticated
    @GET
    @Path("closed")
    public Set<Country> closed() {

        Principal identity = securityIdentity.getPrincipal();
        if (securityIdentity.isAnonymous()) {
            log.info ("SecurityIdentity: Anonymous");
        } else {
            log.info ("SecurityIdentity: Name = " + identity.getName());
        }

        log.info ("JWT Subject = " + jwt.getSubject());
        log.info ("JWT Issuer = " + jwt.getIssuer());
        if (jwt.getAudience() != null)
            jwt.getAudience().forEach(s->log.info ("JWT Audience = " + s));
        else
            log.info ("JWT Audience = null");   
        
        return countries;
    }

    @PermitAll
    @GET
    @Path("open")
    public Set<Country> open() {

        Principal identity = securityIdentity.getPrincipal();
        if (securityIdentity.isAnonymous()) {
            log.info ("SecurityIdentity: Anonymous");
        } else {
            log.info ("SecurityIdentity: Name = " + identity.getName());
        }

        log.info ("JWT Subject = " + jwt.getSubject());
        log.info ("JWT Issuer = " + jwt.getIssuer());
        if (jwt.getAudience() != null)
            jwt.getAudience().forEach(s->log.info ("JWT Audience = " + s));
        else
            log.info ("JWT Audience = null");   
        
        return countries;
    }


}

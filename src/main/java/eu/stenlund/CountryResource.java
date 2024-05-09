package eu.stenlund;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Set;

import org.jboss.logging.Logger;

import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;

@Path("/countries")
public class CountryResource {

    private Set<Country> countries = Collections.newSetFromMap(Collections.synchronizedMap(new LinkedHashMap<>()));
	private static final Logger log = Logger.getLogger("CountryResource");

    @Inject
    public SecurityIdentity securityIdentity;

    public CountryResource() {
        countries.add(new Country("Apple", "Winter fruit"));
        countries.add(new Country("Pineapple", "Tropical fruit"));
    }

    @PermitAll
    @GET
    public Set<Country> list() {
        log.info (securityIdentity.getPrincipal());
        return countries;
    }

    @PermitAll
    @POST
    public Set<Country> add(Country country) {
        countries.add(country);
        return countries;
    }

    @PermitAll
    @DELETE
    public Set<Country> delete(Country country) {
        countries.removeIf(existingFruit -> existingFruit.name.contentEquals(country.name));
        return countries;
    }  
}

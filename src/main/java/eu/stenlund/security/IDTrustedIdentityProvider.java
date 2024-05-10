package eu.stenlund.security;

import org.jboss.logging.Logger;

import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.TrustedAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class IDTrustedIdentityProvider implements IdentityProvider<TrustedAuthenticationRequest> {

    private static final Logger log = Logger.getLogger(IDTrustedIdentityProvider.class);

    @Override
    public Class<TrustedAuthenticationRequest> getRequestType() {
        return TrustedAuthenticationRequest.class;
    }

    protected QuarkusSecurityIdentity.Builder populateSecurityIdentifier(String user) {
        QuarkusSecurityIdentity.Builder builder = QuarkusSecurityIdentity.builder();
        if (user != null) {
            builder.setPrincipal(new QuarkusPrincipal(user));
            builder.setAnonymous(false);
        } else {
            builder.setAnonymous(true);
        }
        return builder;
    }

    @Override
    public Uni<SecurityIdentity> authenticate(TrustedAuthenticationRequest request, AuthenticationRequestContext context) {
            String user = request.getPrincipal();
            if (user != null)
                log.info ("User principal = " + user);
            else
                log.info ("User principal is anonymous");
            return Uni.createFrom().item(populateSecurityIdentifier(user).build());
    }        
}

package eu.stenlund.idproxy.security;

import java.net.URISyntaxException;

import org.apache.hc.core5.net.URIBuilder;
import org.jboss.logging.Logger;

import eu.stenlund.idproxy.IDProxy;
import io.quarkus.smallrye.jwt.runtime.auth.JWTAuthMechanism;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Alternative;
import jakarta.inject.Inject;


/**
 * This class represents an alternative authentication mechanism for JWT authentication.
 * It extends the JWTAuthMechanism class and provides additional functionality specific to the IDProxy application.
 * 
 * The IDJwtAuthMechanism class is an application-scoped class that is used to handle the authentication challenge
 * for the IDProxy application. It generates a redirect URI for the SAML2 login page and returns it as a challenge
 * to the client.
 * 
 * This class is an alternative implementation of the JWTAuthMechanism and has a priority of 1, meaning that it will
 * be used instead of the default implementation if both are available.
 * 
 * The IDJwtAuthMechanism class is injected with an instance of the IDProxy class, which provides access to the base URL
 * of the IDProxy application.
 */
@Alternative
@Priority(1)
@ApplicationScoped
public class IDJwtAuthMechanism extends JWTAuthMechanism {


    private static final Logger log = Logger.getLogger(IDJwtAuthMechanism.class);

    @Inject IDProxy idProxy;
   
    public IDJwtAuthMechanism() {
        super(null);
    }

    /**
        * Generates the challenge data for the authentication mechanism.
        *
        * @param context The routing context.
        * @return A Uni containing the challenge data.
        */
    @Override
    public Uni<ChallengeData> getChallenge(RoutingContext context) {
        ChallengeData challengeData = null;
        try {
            URIBuilder uriBuilder = new URIBuilder(idProxy.getBaseURL()).appendPathSegments("SAML2", "login").addParameter("return", context.request().absoluteURI());
            challengeData = new ChallengeData(302, "Location", uriBuilder.build().toString());
        } catch (URISyntaxException e) {
            log.warn("CHALLENGE: Failed to build URI: "+e.getMessage()); 
        }
        return Uni.createFrom().item(challengeData);
    }
}

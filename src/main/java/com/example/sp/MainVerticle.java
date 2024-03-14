package com.example.sp;

import io.vertx.core.*;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.StaticHandler;

//imports for auth with SAML
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.vertx.VertxProfileManager;
import org.pac4j.vertx.VertxWebContext;
import org.pac4j.vertx.context.session.VertxSessionStore;
import org.pac4j.core.context.session.SessionStore;
import io.vertx.ext.web.sstore.LocalSessionStore;
import org.pac4j.vertx.handler.impl.CallbackHandler;
import org.pac4j.vertx.handler.impl.CallbackHandlerOptions;
import org.pac4j.vertx.handler.impl.SecurityHandlerOptions;
import org.pac4j.vertx.handler.impl.SecurityHandler;
import org.pac4j.core.config.Config;
import org.pac4j.vertx.auth.Pac4jAuthProvider;
import java.io.File;
import java.util.List;
import java.util.Map;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.config.SAML2Configuration;
import io.vertx.ext.web.handler.SessionHandler;
import static io.vertx.core.http.HttpHeaders.CONTENT_TYPE;
import static io.vertx.core.http.HttpHeaders.TEXT_HTML;
import org.pac4j.vertx.handler.impl.LogoutHandler;
import org.pac4j.vertx.handler.impl.LogoutHandlerOptions;
import io.vertx.ext.web.templ.handlebars.HandlebarsTemplateEngine;

public class MainVerticle extends AbstractVerticle {


  @Override
  public void start(Promise<Void> startPromise) throws Exception {

    //The following httpServerOptions method allows you to set the maximum size of a form's attributes.
    // It is necessary to modify it as SAML uses POST requests and an html form (<input> <form>... ) to send the token to send the token.
    HttpServerOptions serverOptions = new HttpServerOptions().setMaxFormAttributeSize(65536);
                                                              //.setSsl(true)
                                                             // .setKeyStoreOptions(new JksOptions().setPath("cert/keyStore.jks").setPassword("password"));

    HttpServer server = vertx.createHttpServer(serverOptions);
    Router router = Router.router(vertx);
    LocalSessionStore vertxSessionStore = LocalSessionStore.create(vertx);
    SessionStore sessionStore = new VertxSessionStore(vertxSessionStore);
    Pac4jAuthProvider authProvider = new Pac4jAuthProvider();
    SessionHandler sessionHandler = SessionHandler.create(vertxSessionStore);

    //static index page http://localhost:8888/login
    router.get("/login").handler(StaticHandler.create("src/main/resources/static/login.html"));

    //Pac4j configuration
    SAML2Client saml2Client = this.saml2Client();
    Config config = new Config("http://localhost:8888/callback",saml2Client);

    //User session management. If I comment out this line then it does not find the protected resources, ie,
    //HTTP displays the error message "resource not found" when trying to access msg.html
    router.route().handler(sessionHandler);

    //Protected paths
    SecurityHandlerOptions options = new SecurityHandlerOptions().setClients("SAML2Client");
    //http://localhost:8888/msg.html
    router.route("/msg.html").handler(new SecurityHandler(vertx, sessionStore, config, authProvider,options));
    router.get("/msg.html").handler(rc ->{
      rc.response().putHeader(CONTENT_TYPE, TEXT_HTML);
      rc.next();
    });
    router.get("/msg.html").handler(generateMSG(vertx, sessionStore));

    //Callback path
    CallbackHandlerOptions callbackHandlerOptions = new CallbackHandlerOptions()
                .setDefaultUrl("/")
                .setMultiProfile(true);
    CallbackHandler callbackHandler = new CallbackHandler(vertx, sessionStore, config, callbackHandlerOptions);
    router.get("/callback").handler(callbackHandler);
    //The following two lines of code are needed in order to process the SAMLResponse sent by the IdP
    router.post("/callback").handler(BodyHandler.create().setMergeFormAttributes(true));
    router.post("/callback").handler(callbackHandler);

    //MCentral logout handler of the user session. That is the SLO
    //This performs the logout with the IdP and the rest of the SPs.
    //But each SP must log out from itself, i.e. delete the user's session from the SP itself.
    //If the SP does not do this, the user will still be able to access the resources of that SP as the SP will still be able to access the resources of that SP.
    //retains the user's session locally
    router.get("/logout").handler(SingleLogouthandler(vertx, config, sessionStore));

    //Starting the vertx server
    server.requestHandler(router).listen(8888, http -> {
      if (http.succeeded()) {
            startPromise.complete();
            System.out.println("HTTP server started on port 8888");
          } else {
            startPromise.fail(http.cause());
          }
    });
  }

  //Method for setting the SAML client configuration
  private SAML2Client saml2Client(){
    SAML2Configuration cfg = new SAML2Configuration("samlConfig/samlKeystore.jks",
                                    "pac4j-demo-passwd",
                                    "pac4j-demo-passwd",
                                    "samlConfig/idp-metadata.xml");

    cfg.setAuthnRequestBindingType(SAMLConstants.SAML2_POST_BINDING_URI);
    cfg.setResponseBindingType(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
    //By default it will set the same ACS (Assertion Consumer Service) that entityID gives to the SAML2Client.
    cfg.setServiceProviderEntityId("http://localhost:8888/callback?client_name=SAML2Client");
    cfg.setServiceProviderMetadataPath(new File("target", "sp-metadata.xml").getAbsolutePath());
    //I indicate that I sign the assertion and logout request sent to the IdP.
    //In addition to specifying that the assertions sent by the IdP must also be signed.
    cfg.setAuthnRequestSigned(true);
    cfg.setSpLogoutRequestSigned(true);
    cfg.setWantsAssertionsSigned(true);

    return new SAML2Client(cfg);
  }

  //function for specifying pac4j logout handler settings
  private Handler<RoutingContext> SingleLogouthandler(Vertx vertx, Config config, SessionStore sessionStore){
    LogoutHandlerOptions logoutOptions = new LogoutHandlerOptions()
        .setCentralLogout(true)
        .setLocalLogout(true)
        .setDefaultUrl("http://localhost:8888/login"); //Necesario a true para que el SP haga también logout
    return new LogoutHandler(vertx, sessionStore, logoutOptions, config);
  }

  //method to display the protected resource with the attributes returned by the SAML token
  private Handler<RoutingContext> generateMSG(Vertx vertx, SessionStore sessionStore){
        HandlebarsTemplateEngine engine = HandlebarsTemplateEngine.create(vertx);
        return rc -> {
            //retrieve the user attributes stored in a list of profiles.
            List<UserProfile> profile = this.getUserProfilesSAML(rc, sessionStore);
            profile.get(0).getAttributes();
            Map<String, Object> attributes = profile.get(0).getAttributes();
            rc.put("username", attributes.get("uid"));
            rc.put("rol", attributes.get("eduPersonAffiliation"));
            rc.put("attributes", attributes);
            engine.render(rc.data(), "templates/msg.hbs", res -> {
                if (res.succeeded()) {
                    rc.response().end(res.result());
                  } else {
                    rc.fail(res.cause());
                  }
            });
        };
  }

  //A list of profiles is created in order to access the attributes of the user's SAML token. This is done using the sessionStore
  private List<UserProfile> getUserProfilesSAML(RoutingContext rc, SessionStore sessionStore){
    ProfileManager profileManager = new VertxProfileManager(new VertxWebContext(rc, sessionStore), (VertxSessionStore) sessionStore);
    return profileManager.getProfiles();
  }

}

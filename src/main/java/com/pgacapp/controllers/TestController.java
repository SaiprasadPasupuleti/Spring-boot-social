package com.pgacapp.controllers;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

@EnableOAuth2Client
@RestController
public class TestController {

    @Value("${google.clientId}")
    private String clientId;

    @Value("${google.clientSecret}")
    private String clientSecret;

    @Value("${google.accessTokenUri}")
    private String accessTokenUri;

    @Value("${google.userAuthorizationUri}")
    private String userAuthorizationUri;

    @Value("${google.redirectUri}")
    private String redirectUri;

    @Value("${google.deviceId}")
    private String deviceId;

    @Value("${google.deviceName}")
    private String deviceName;

    @Value("${google.jwkUrl}")
    private String jwkUrl;
    OAuth2RestTemplate template;

    OAuth2AccessToken accessToken;

    @Autowired
    @Qualifier("oauth2ClientContext")
    OAuth2ClientContext oauth2ClientContext;

    OpenIdConnectUserDetails user;

    @RequestMapping(value = "/appLogin")
    public OpenIdConnectUserDetails getDetails() {
        String id_token = null;
        List<String> errors= new ArrayList<>();
        try {
            template = new OAuth2RestTemplate(googleOpenId(), oauth2ClientContext);
            oauth2ClientContext.setAccessToken(null);
            accessToken = template.getAccessToken();
            id_token = accessToken.getAdditionalInformation().get("id_token").toString();
            String kid = JwtHelper.headers(id_token)
                    .get("kid");
            final Jwt tokenDecoded = JwtHelper.decodeAndVerify(id_token, verifier(kid));
            final Map<String, String> authInfo = new ObjectMapper().readValue(tokenDecoded.getClaims(), Map.class);
            user = new OpenIdConnectUserDetails(authInfo, accessToken);
            verifyGoogleAccessToken(errors, id_token);
        } catch (final Exception e) {
            throw new BadCredentialsException("Could not obtain access token", e);
        }
        System.out.println("ID TOKEN---" + accessToken.getAdditionalInformation().get("id_token").toString());
        return user;
    }

    public OAuth2ProtectedResourceDetails googleOpenId() {
        final AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
        details.setClientId(clientId);
        details.setClientSecret(clientSecret);
        details.setAccessTokenUri(accessTokenUri);
        details.setUserAuthorizationUri(userAuthorizationUri);
        details.setScope(Arrays.asList("openid", "email"));
        details.setPreEstablishedRedirectUri(redirectUri);
        details.setUseCurrentUri(false);
        return details;
    }

    private RsaVerifier verifier(String kid) throws Exception {
        JwkProvider provider = new UrlJwkProvider(new URL(jwkUrl));
        Jwk jwk = provider.get(kid);
        return new RsaVerifier((RSAPublicKey) jwk.getPublicKey());
    }
    private void verifyGoogleAccessToken( List<String> errors, String accessToken) {
        try {
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), new JacksonFactory())
                    .setAudience(Collections.singletonList(clientId)).build();
            GoogleIdToken idToken = verifier.verify(accessToken);
            if (idToken != null) {
                GoogleIdToken.Payload payload = idToken.getPayload();
                String userId = payload.getSubject();
                System.out.println("userId---"+userId);
             /*   loginRequest.setUsername(userId);
                loginRequest.setPassword(userId);*/

            } else {
                errors.add("INVALID_ACCESS_TOKEN");
            }
        } catch (Exception ex) {
            errors.add("ACCESS_TOKEN_VERIFICATION_ERROR");
        }
    }
}

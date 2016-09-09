package com.autoscout24.dotcms.authentication.cli;

import com.autoscout24.dotcms.authentication.api.Auth02Api;
import org.scribe.builder.ServiceBuilder;
import org.scribe.model.*;
import org.scribe.oauth.OAuthService;

import java.util.Random;
import java.util.Scanner;

public class Auth02Example
{
  private static final String PROTECTED_RESOURCE_URL = "https://jostick.eu.auth0.com/userinfo?oauth_token=";
  private static final Token EMPTY_TOKEN = null;

  public static void main(String[] args)
  {
    // Replace these with your own api key and secret
    String apiKey = System.getProperty("api.key");
    String apiSecret = System.getProperty("api.secret");
    OAuthService service = new ServiceBuilder()
                                  .provider(Auth02Api.class)
                                  .apiKey(apiKey)
                                  .apiSecret(apiSecret)
                                  .scope("openid email given_name family_name roles")
                                  .callback("http://localhost:8080/app/oauth2/callback")
                                  .build();
    String state = "secret" + new Random().nextInt(999_999);
    ((Auth02Api)service.getApi()).configure(state);
    Scanner in = new Scanner(System.in);

    System.out.println("=== Auth02's OAuth Workflow ===");
    System.out.println();

    // Obtain the Authorization URL
    System.out.println("Fetching the Authorization URL...");
    String authorizationUrl = service.getAuthorizationUrl(EMPTY_TOKEN);
    System.out.println("Got the Authorization URL!");
    System.out.println("Now go and authorize Scribe here:");
    System.out.println(authorizationUrl);
    System.out.println("And paste the authorization code here");
    System.out.print(">>");
    Verifier verifier = new Verifier(in.nextLine());
    System.out.println();

    System.out.println("And paste the state from server here. We have set 'secretState'='" + state + "'.");
    System.out.print(">>");
    final String value = in.nextLine();
    if (state.equals(value)) {
      System.out.println("State value does match!");
    } else {
      System.out.println("Ooops, state value does not match!");
      System.out.println("Expected = " + state);
      System.out.println("Got      = " + value);
      System.out.println();
    }

    // Trade the Request Token and Verfier for the Access Token
    System.out.println("Trading the Request Token for an Access Token...");
    Token accessToken = service.getAccessToken(EMPTY_TOKEN, verifier);
    System.out.println("Got the Access Token!");
    System.out.println("(if your curious it looks like this: " + accessToken + " )");
    System.out.println();

    // Now let's go and ask for a protected resource!
    System.out.println("Now we're going to access a protected resource...");
    OAuthRequest request = new OAuthRequest(Verb.GET, PROTECTED_RESOURCE_URL + accessToken.getToken());
    service.signRequest(accessToken, request);
    Response response = request.send();
    System.out.println("Got it! Lets see what we found...");
    System.out.println();
    System.out.println(response.getCode());
    System.out.println(response.getBody());

    System.out.println();
    System.out.println("Thats it man! Go and build something awesome! :)");

  }
}

package com.phnx.oauth;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.MalformedURLException;
import java.util.concurrent.ExecutionException;

import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import com.microsoft.aad.adal4j.AuthenticationResult;
import com.phnx.oauth.exception.AuthenticationException;
import com.phnx.oauth.impl.AzureAdB2CAuthentication;

/**
 * Unit test for simple App.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class TestAuthentication {
	
	static AuthenticationFactory authenticationFactory;
	
	static AzureAdB2CAuthentication azureAdB2CAuthentication;
	
	static AuthenticationResult authenticationResult;
	
	private final static String CLIENT_ID = "c2f4411b-0b77-41******************";
	private final static String CLIENT_SECRET = "9Aw*******************2";
	private final static String APPURI = "https://********.onmicrosoft.com/api";
	private final static String jwt = "eyJ0eXAiOiJKV1QiLCJub25jZSI6IkFRQUJBQUFBQUFEWDhHQ2k2SnM2U0s4MlRzRDJQYjdyN3I1eGpMQ1ZlRE9rc25UU0pudU5rOUdEcDdCLUYtNFpvb25PZjlkaXFhNE5ZdEU1ZXB1clFKQ2pPRzlrNkRoU0x6Q2p3blRvUWVQSTc4SXBzUmVibENBQSIsImFsZyI6IlJTMjU2IiwieDV0IjoiaUJqTDFSY3F6aGl5NGZweEl4ZFpxb2hNMllrIiwia2lkIjoiaUJqTDFSY3F6aGl5NGZweEl4ZFpxb2hNMllrIn0.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8xMDU2ZDhmYy1kMmM0LTQ5ZGItYWViZC03YjhmMDI0MGM5YjMvIiwiaWF0IjoxNTI4MTM2ODg3LCJuYmYiOjE1MjgxMzY4ODcsImV4cCI6MTUyODE0MDc4NywiYWlvIjoiWTJkZ1lEaTk4cWgrc0ZUcyttL2F1N1NqTGlncUF3QT0iLCJhcHBfZGlzcGxheW5hbWUiOiJUcmFuc2FjdGlvbkFQUCIsImFwcGlkIjoiZWQ1ZGIzOTItNzQ0MC00NGUwLTkwODYtNWU3ZDQ0Y2ExZDhjIiwiYXBwaWRhY3IiOiIxIiwiZV9leHAiOjI2MjgwMCwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMTA1NmQ4ZmMtZDJjNC00OWRiLWFlYmQtN2I4ZjAyNDBjOWIzLyIsInRpZCI6IjEwNTZkOGZjLWQyYzQtNDlkYi1hZWJkLTdiOGYwMjQwYzliMyIsInV0aSI6IjV4N3hBR1gwbjB1c25PUUZYenNmQUEiLCJ2ZXIiOiIxLjAifQ.VRKxZJVbEsvKQLfsQkYIkrYyrxkvZPDez_5wkKtxAO3RQGbYODJtmi35q8EhtpqoCM8cWgdMAo5BGPsMHFf4vE7iqvLYssVivnDPb0tF9jGWnf5zVzJ648ZYu9i7Hj9Pny0wxMUvaXz-2f7LsGILos1nk6BqjSK2IP6WAI1hzKZZIfbGCRXl7tuI_jGmAk-fW7vdOylF2DLRaUw5IqhmwtLgsUy7oYQOIJRz35kKAhBQVCCYo6Ij00VlpfQ0f23MssdIH2CAza6NFTh0IirwWMsIWWlW5mV_BL3dEuG8NXGilOzbaFy4KVaHzXWg6xBpyrEySxulx75R0k3dpRAIcQ";
	
	@SuppressWarnings("static-access")
	@BeforeClass
	public static void init() {

		try {
			azureAdB2CAuthentication = authenticationFactory.getAzureAdB2CAuthInstance();
		} catch (AuthenticationException e) {
			e.printStackTrace();
		}

	}
	@Test
	public void testGetAccessToken() throws MalformedURLException, AuthenticationException, InterruptedException, ExecutionException{
		authenticationResult = azureAdB2CAuthentication.getAccessToken(APPURI, CLIENT_ID, CLIENT_SECRET);
		String token = authenticationResult.getAccessToken();
		System.out.println(token);
		assertNotNull(token);
	}
	
	@Test
	public void testVerifyAccessToken() throws AuthenticationException{
		boolean b = azureAdB2CAuthentication.verifyAccessToken(authenticationResult.getAccessToken());
		assertTrue(b);
	}
	
	@Test
	public void testVerifyWrongAccessToken() throws AuthenticationException{
		boolean b = azureAdB2CAuthentication.verifyAccessToken(jwt);
		assertFalse(b);
	}
    
}

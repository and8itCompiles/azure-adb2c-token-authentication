package com.phnx.oauth.impl;

import java.net.MalformedURLException;
import java.security.cert.CertificateException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.json.JSONException;

import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.phnx.oauth.AzureAdJwtToken;
import com.phnx.oauth.constant.AuthConstants;
import com.phnx.oauth.exception.AuthenticationException;
import com.phnx.oauth.service.AbstractAuthentication;
/**
 * 
 *
 */
public class AzureAdB2CAuthentication extends AbstractAuthentication {

	@Override
	public AuthenticationResult getAccessToken(String appUri, String clientId, String clientSecret)
			throws AuthenticationException, MalformedURLException, InterruptedException, ExecutionException {
		 AuthenticationContext context;
	        AuthenticationResult result;
	        ExecutorService service = null;
	        try {
	            service = Executors.newFixedThreadPool(1);
	            context = new AuthenticationContext(AuthConstants.AUTHORITY, false, service);
	            ClientCredential credential = new ClientCredential(clientId, clientSecret);
	            Future<AuthenticationResult> future = context.acquireToken(
	            		appUri, credential,
	                    null);
	            result = future.get();
	        } finally {
	            service.shutdown();
	        }

	        if (result == null) {
	            throw new AuthenticationException( "authentication result was null");
	        }
	        return result;
	}

	@Override
	public boolean verifyAccessToken(String token) throws AuthenticationException {
		boolean verified = false;
		
		 AzureAdJwtToken jwt;
		try {
			jwt = new AzureAdJwtToken(token);
		} catch (JSONException e) {
			throw new AuthenticationException(e.getMessage());
		}
         
         try{
       	  jwt.verify();
       	  verified = true;
         }catch (CertificateException e) {
        	 verified = false;
         } catch (Exception e) {
        	 verified = false;
         }
		return verified;
	}

}

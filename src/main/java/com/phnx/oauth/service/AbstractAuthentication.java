package com.phnx.oauth.service;

import java.net.MalformedURLException;
import java.util.concurrent.ExecutionException;

import com.microsoft.aad.adal4j.AuthenticationResult;
import com.phnx.oauth.exception.AuthenticationException;
/**
 * 
 *
 */
public abstract class AbstractAuthentication implements iAuthentication {
	/**
	 * This method will return the Access token for authentication
	 * 
	 * @param appUri
	 * @param clientId
	 * @param clientSecret
	 * @return AuthenticationResult
	 * @throws MalformedURLException 
	 * @throws ExecutionException 
	 * @throws InterruptedException 
	 */
	public abstract AuthenticationResult getAccessToken(String appUri, String clientId, String clientSecret)
			throws AuthenticationException, MalformedURLException, InterruptedException, ExecutionException;
	
	/**
	 * This method verifies the token 
	 * 
	 * @param token
	 * @return
	 * @throws AuthenticationException
	 */
	public abstract boolean verifyAccessToken(String token) throws AuthenticationException;

}

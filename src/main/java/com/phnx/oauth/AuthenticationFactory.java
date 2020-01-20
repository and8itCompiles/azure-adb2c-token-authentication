package com.phnx.oauth;

import com.phnx.oauth.exception.AuthenticationException;
import com.phnx.oauth.impl.AzureAdB2CAuthentication;

/**
 * 
 *
 */
public class AuthenticationFactory {
	/**
	 * Instantiate the new AuthenticationFacory
	 */
	private AuthenticationFactory() {}
	/**
	 * Gets the AzureAdB2CAuthentication Instance.
	 * 
	 * @return
	 * @throws AuthenticationException
	 */
	public static AzureAdB2CAuthentication getAzureAdB2CAuthInstance() throws AuthenticationException{
		return new AzureAdB2CAuthentication();
	}
	
	

}

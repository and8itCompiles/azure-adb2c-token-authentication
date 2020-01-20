package com.phnx.oauth.exception;

/**
 * 
 *
 */
public class AuthenticationException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 7720202100182183785L;
	
  	/** The error msg. */
  	private final String errorMsg;
  	/**
  	 * Instantiate the new Authentication Exception
  	 * @param codes
  	 */
  	public AuthenticationException(String errorMsg){
  		this.errorMsg = errorMsg;
  	}
  	
	  /**
  	 * Gets the error msg.
  	 *
  	 * @return the error msg
  	 */
  	public String getErrorMsg() {
	    return errorMsg;
	  }

}

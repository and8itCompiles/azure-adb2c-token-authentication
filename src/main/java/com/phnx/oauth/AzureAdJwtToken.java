package com.phnx.oauth;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.util.Base64;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
/**
 * 
 *
 */
public class AzureAdJwtToken {

    protected final String token;
    protected final String kid;
    protected final String issuer;
    
    public AzureAdJwtToken(String token) throws JSONException {
        this.token = token;
        String[] parts = token.split("\\.");

        String headerStr = new String(Base64.getUrlDecoder().decode((parts[0])));
        JSONObject header = new JSONObject(headerStr);
        
        kid = header.getString("kid");

        String payloadStr = new String(Base64.getUrlDecoder().decode((parts[1])));
        JSONObject payload = new JSONObject(payloadStr);
        
        issuer = payload.getString("iss");
    }
    
  /**
   * 
   * 
   * @return
   * @throws IOException
   * @throws CertificateException
   * @throws JSONException
   */
    protected PublicKey loadPublicKey() throws IOException, CertificateException, JSONException {

        String openidConfigStr = readUrl("https://login.microsoftonline.com/1056d8fc-******************/v2.0/.well-known/openid-configuration");
        JSONObject openidConfig = new JSONObject(openidConfigStr);

        String jwksUri = openidConfig.getString("jwks_uri");
        
        String jwkConfigStr = readUrl(jwksUri);
        JSONObject jwkConfig = new JSONObject(jwkConfigStr);
        
        JSONArray keys = jwkConfig.getJSONArray("keys");
        for (int i = 0; i < keys.length(); i++) {
            JSONObject key = keys.getJSONObject(i);

            String kid = key.getString("kid");
            String x5c = key.getJSONArray("x5c").getString(0);

            String keyStr = "-----BEGIN CERTIFICATE-----\r\n";
            String tmp = x5c;
            while (tmp.length() > 0) {
                if (tmp.length() > 64) {
                    String x = tmp.substring(0, 64);
                    keyStr += x + "\r\n";
                    tmp = tmp.substring(64);
                } else {
                    keyStr += tmp + "\r\n";
                    tmp = "";
                }
            }
            keyStr += "-----END CERTIFICATE-----\r\n";
            
            // read certification
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            InputStream stream = new ByteArrayInputStream(keyStr.getBytes(StandardCharsets.US_ASCII));
            X509Certificate cer = (X509Certificate) fact.generateCertificate(stream);
            
            // get public key from certification
            PublicKey publicKey = cer.getPublicKey();
            
            if (this.kid.equals(kid)) {
                return publicKey;
            }
        }
        return null;
    }
    /**
     * 
     * @param url
     * @return
     * @throws IOException
     */
    protected String readUrl(String url) throws IOException {
        URL addr = new URL(url);
        StringBuilder sb = new StringBuilder();
        try (BufferedReader in = new BufferedReader(new InputStreamReader(addr.openStream()))) {
            String inputLine = null;
            while ((inputLine = in.readLine()) != null) {
                sb.append(inputLine);
            }
        }
        return sb.toString();
    }
    /**
     * 
     * @throws IOException
     * @throws CertificateException
     * @throws JSONException
     */
    public void verify() throws IOException, CertificateException, JSONException {
        PublicKey publicKey = loadPublicKey();
        JWTVerifier verifier = JWT.require(Algorithm.RSA256((RSAKey) publicKey)).withIssuer(issuer).build();
        DecodedJWT jwt = verifier.verify(token);
    }

    /**
     * 
     */
    @Override
    public String toString() {
        return "AzureAdJwtToken [issuer=" + issuer + "]";
    }
}

package org.mitre.openid.connect.service.impl;

import java.util.Date;

import org.mitre.jwt.signer.service.JwtSigningAndValidationService;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntityFactory;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntityFactory;
import org.mitre.oauth2.repository.OAuth2TokenRepository;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.mitre.openid.connect.model.IdToken;
import org.mitre.openid.connect.token.IdTokenGeneratorService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.code.AuthorizationRequestHolder;

import com.google.common.base.Strings;

public class OpenIdConnectTokenService extends DefaultOAuth2ProviderTokenService {
	
	private static Logger logger = LoggerFactory.getLogger(OpenIdConnectTokenService.class);

	@Autowired
	private OAuth2TokenRepository tokenRepository;
	
	@Autowired
	private ClientDetailsEntityService clientDetailsService;
	
	@Autowired
	private OAuth2AccessTokenEntityFactory accessTokenFactory;
	
	@Autowired
	private OAuth2RefreshTokenEntityFactory refreshTokenFactory;

	@Autowired
	private ConfigurationPropertiesBean configBean;
	
	@Autowired
	private IdTokenGeneratorService idTokenService;
	
	@Autowired
	private JwtSigningAndValidationService jwtService;
	
	/**
	 * Insert the ID token
	 */
	@Override
	public void enhanceAccessToken(OAuth2AccessToken token, AuthorizationRequestHolder requestHolder) {
		
		OAuth2AccessTokenEntity token2 = (OAuth2AccessTokenEntity) token;
		AuthorizationRequest authRequest = requestHolder.getAuthenticationRequest();
		Authentication userAuth = requestHolder.getUserAuthentication();
		
		token2.getJwt().getClaims().setAudience(authRequest.getClientId());
		
		token2.getJwt().getClaims().setIssuer(configBean.getIssuer());

		token2.getJwt().getClaims().setIssuedAt(new Date());
		// handle expiration
		token2.getJwt().getClaims().setExpiration(token.getExpiration());
		
		/**
		 * Authorization request scope MUST include "openid", but access token request 
		 * may or may not include the scope parameter. As long as the AuthorizationRequest 
		 * has the proper scope, we can consider this a valid OpenID Connect request.
		 */
		if (authRequest.getScope().contains("openid")) {

			String userId = userAuth.getName();
		
			IdToken idToken = idTokenService.generateIdToken(userId, configBean.getIssuer());
			idToken.getClaims().setAudience(authRequest.getClientId());
			idToken.getClaims().setIssuedAt(new Date());
			idToken.getClaims().setIssuer(configBean.getIssuer());
			
			String nonce = authRequest.getParameters().get("nonce");
			if (!Strings.isNullOrEmpty(nonce)) {
				idToken.getClaims().setNonce(nonce);
			}
			
			token2.setIdToken(idToken);
		}
		
		logger.info("Enhancing token");
		
		return;
	}
	
	/**
	 * Sign the token
	 */
	@Override
	public void finishAccessToken(OAuth2AccessToken token) {
		
		OAuth2AccessTokenEntity token2 = (OAuth2AccessTokenEntity) token;
		
		logger.info("Finishing token");
		
		jwtService.signJwt(token2.getJwt());
		
		if (token2.getIdToken() instanceof IdToken) {
			jwtService.signJwt(token2.getIdToken());
		}
		
		return;
	}

	/**
	 * @return the tokenRepository
	 */
	public OAuth2TokenRepository getTokenRepository() {
		return tokenRepository;
	}

	/**
	 * @param tokenRepository the tokenRepository to set
	 */
	public void setTokenRepository(OAuth2TokenRepository tokenRepository) {
		this.tokenRepository = tokenRepository;
	}

	/**
	 * @return the clientDetailsService
	 */
	public ClientDetailsEntityService getClientDetailsService() {
		return clientDetailsService;
	}

	/**
	 * @param clientDetailsService the clientDetailsService to set
	 */
	public void setClientDetailsService(ClientDetailsEntityService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	/**
	 * @return the accessTokenFactory
	 */
	public OAuth2AccessTokenEntityFactory getAccessTokenFactory() {
		return accessTokenFactory;
	}

	/**
	 * @param accessTokenFactory the accessTokenFactory to set
	 */
	public void setAccessTokenFactory(OAuth2AccessTokenEntityFactory accessTokenFactory) {
		this.accessTokenFactory = accessTokenFactory;
	}

	/**
	 * @return the refreshTokenFactory
	 */
	public OAuth2RefreshTokenEntityFactory getRefreshTokenFactory() {
		return refreshTokenFactory;
	}

	/**
	 * @param refreshTokenFactory the refreshTokenFactory to set
	 */
	public void setRefreshTokenFactory(OAuth2RefreshTokenEntityFactory refreshTokenFactory) {
		this.refreshTokenFactory = refreshTokenFactory;
	}
	

}

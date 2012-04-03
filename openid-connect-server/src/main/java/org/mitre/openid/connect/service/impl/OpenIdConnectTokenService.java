package org.mitre.openid.connect.service.impl;

import org.mitre.oauth2.model.OAuth2AccessTokenEntityFactory;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntityFactory;
import org.mitre.oauth2.repository.OAuth2TokenRepository;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

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

	
	
	/**
	 * Insert the ID token
	 */
	@Override
	public void enhanceAccessToken(OAuth2AccessToken token) {
		
		logger.info("Enhancing token");
		
		return;
	}
	
	/**
	 * Sign the token
	 */
	@Override
	public void finishAccessToken(OAuth2AccessToken token) {
		
		logger.info("Finishing token");
		
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

package org.mitre.oauth2.service;

import java.util.List;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.code.AuthorizationRequestHolder;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

public interface OAuth2TokenEntityService extends AuthorizationServerTokenServices, ResourceServerTokenServices {

	public OAuth2AccessTokenEntity getAccessToken(String accessTokenValue);
	
	public void enhanceAccessToken(OAuth2AccessToken token, AuthorizationRequestHolder requestHolder);
	
	public void finishAccessToken(OAuth2AccessToken token);
	
	public OAuth2RefreshTokenEntity getRefreshToken(String refreshTokenValue);

	public void revokeRefreshToken(OAuth2RefreshTokenEntity refreshToken);

	public void revokeAccessToken(OAuth2AccessTokenEntity accessToken);
	
	public List<OAuth2AccessTokenEntity> getAccessTokensForClient(ClientDetailsEntity client);
	
	public List<OAuth2RefreshTokenEntity> getRefreshTokensForClient(ClientDetailsEntity client);

	public void clearExpiredTokens();
	
	public OAuth2AccessTokenEntity saveAccessToken(OAuth2AccessTokenEntity accessToken);
	
	public OAuth2RefreshTokenEntity saveRefreshToken(OAuth2RefreshTokenEntity refreshToken);
	
}

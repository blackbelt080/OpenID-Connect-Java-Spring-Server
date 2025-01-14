/*******************************************************************************
 * Copyright 2012 The MITRE Corporation
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package org.mitre.oauth2.service;

import java.util.List;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

public interface OAuth2TokenEntityService extends AuthorizationServerTokenServices, ResourceServerTokenServices {

	public OAuth2AccessTokenEntity getAccessToken(String accessTokenValue);
	
	public OAuth2RefreshTokenEntity getRefreshToken(String refreshTokenValue);

	public void revokeRefreshToken(OAuth2RefreshTokenEntity refreshToken);

	public void revokeAccessToken(OAuth2AccessTokenEntity accessToken);
	
	public List<OAuth2AccessTokenEntity> getAccessTokensForClient(ClientDetailsEntity client);
	
	public List<OAuth2RefreshTokenEntity> getRefreshTokensForClient(ClientDetailsEntity client);

	public void clearExpiredTokens();
	
	public OAuth2AccessTokenEntity saveAccessToken(OAuth2AccessTokenEntity accessToken);
	
	public OAuth2RefreshTokenEntity saveRefreshToken(OAuth2RefreshTokenEntity refreshToken);
	
}

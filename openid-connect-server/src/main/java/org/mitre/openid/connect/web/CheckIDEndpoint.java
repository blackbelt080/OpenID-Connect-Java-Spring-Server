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
package org.mitre.openid.connect.web;

import javax.servlet.http.HttpServletRequest;

import org.mitre.jwt.signer.service.JwtSigningAndValidationService;
import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.mitre.openid.connect.exception.ExpiredTokenException;
import org.mitre.openid.connect.exception.InvalidJwtIssuerException;
import org.mitre.openid.connect.exception.InvalidJwtSignatureException;
import org.mitre.openid.connect.model.IdToken;
import org.mitre.util.Utility;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class CheckIDEndpoint {

	@Autowired
	JwtSigningAndValidationService jwtSignerService;
	
	@Autowired
	private ConfigurationPropertiesBean configBean;
	
	@RequestMapping("/checkid")
	public ModelAndView checkID(@RequestParam("access_token") String tokenString, ModelAndView mav, HttpServletRequest request) {
		
		if (!jwtSignerService.validateSignature(tokenString)) {
			// can't validate 
			throw new InvalidJwtSignatureException(); // TODO: attach a view to this exception
		}
		
		// it's a valid signature, parse the token
		IdToken token = IdToken.parse(tokenString);
		
		// check the expiration
		if (jwtSignerService.isJwtExpired(token)) {
			// token has expired
			throw new ExpiredTokenException(); // TODO create a view for this exception
		}
		
		// check the issuer (sanity check)
		if (!jwtSignerService.validateIssuedJwt(token, configBean.getIssuer())) {
			throw new InvalidJwtIssuerException(); // TODO: create a view for this exception
		}
		
		// pass the claims directly (the view doesn't care about other fields)
		return new ModelAndView("jsonIdTokenView", "entity", token.getClaims());
	}

	public JwtSigningAndValidationService getJwtSignerService() {
		return jwtSignerService;
	}

	public void setJwtSignerService(JwtSigningAndValidationService jwtSignerService) {
		this.jwtSignerService = jwtSignerService;
	}

	public ConfigurationPropertiesBean getConfigBean() {
		return configBean;
	}

	public void setConfigBean(ConfigurationPropertiesBean configBean) {
		this.configBean = configBean;
	}
	
}

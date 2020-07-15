package com.github.demo.configuration;

import com.github.demo.filter.MyUsernamePasswordAuthenticationFilter;
import com.github.demo.service.JwtUserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 在 {@link MyUsernamePasswordAuthenticationFilter} 的最后将 token 交给 provider 做校验，校验结果成功时，应该进行的操作。
 */
public class JsonLoginSuccessHandler implements AuthenticationSuccessHandler{
	
	private JwtUserService jwtUserService;
	
	public JsonLoginSuccessHandler(JwtUserService jwtUserService) {
		this.jwtUserService = jwtUserService;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		// 认证成功，保存用户信息
		String token = jwtUserService.saveUserLoginInfo((UserDetails)authentication.getPrincipal());
		// 将用户信息放到 HTTP 响应头的 Authorization 字段中
		response.setHeader("Authorization", token);
	}
	
}

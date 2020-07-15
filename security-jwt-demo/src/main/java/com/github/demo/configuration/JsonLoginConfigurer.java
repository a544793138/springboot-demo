package com.github.demo.configuration;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import com.github.demo.filter.MyUsernamePasswordAuthenticationFilter;

/**
 * 登录流程组件
 */
public class JsonLoginConfigurer<T extends JsonLoginConfigurer<T, B>, B extends HttpSecurityBuilder<B>> extends AbstractHttpConfigurer<T, B>  {

	private MyUsernamePasswordAuthenticationFilter authFilter;

	public JsonLoginConfigurer() {
		this.authFilter = new MyUsernamePasswordAuthenticationFilter();
	}
	
	@Override
	public void configure(B http) throws Exception {
		// 设置 filter 使用的 AuthenticationManager
		authFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
		// 设置失败的 Handler
		authFilter.setAuthenticationFailureHandler(new HttpStatusLoginFailureHandler());
		// 因为使用 JWT，不讲认证后的 context 放入到 session 中
		authFilter.setSessionAuthenticationStrategy(new NullAuthenticatedSessionStrategy());

		MyUsernamePasswordAuthenticationFilter filter = postProcess(authFilter);
		// 指定 filter 的位置
		http.addFilterAfter(filter, LogoutFilter.class);
	}

	// 设置成功的 Handler，这个 handler 定义成 Bean，所以从外面 set 进来
	public JsonLoginConfigurer<T,B> loginSuccessHandler(AuthenticationSuccessHandler authSuccessHandler){
		authFilter.setAuthenticationSuccessHandler(authSuccessHandler);
		return this;
	}

}

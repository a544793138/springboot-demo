package com.github.demo.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Date;

/**
 * 在 {@link com.github.demo.filter.MyUsernamePasswordAuthenticationFilter} 的最后，我们将用户登录的认证请求交由了 {@link AuthenticationManager} 进行认证。
 * 但其实 {@link AuthenticationManager} 是一个代理接口，它会将认证的工作交由特定的 {@link AuthenticationProvider} 来实现，例如本 demo 中要使用的 {@link DaoAuthenticationProvider}，
 * 因为 spring security 已经实现了，所以可以直接使用。
 * <p>
 * 通过阅读 {@link DaoAuthenticationProvider} 代码可以发现，它是通过 {@link UserDetailsService} 来获取到系统储存的用户信息的。
 * （所以，其实 {@link UserDetailsService} 就是一个 提供/操作 用户信息的服务类）
 * <p>
 * 所以，我们需要写一个自己的 {@link UserDetailsService} 实现类，并将该类注入成 Bean。
 */
public class JwtUserService implements UserDetailsService {

    private PasswordEncoder passwordEncoder;

    public JwtUserService() {
        this.passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();  //默认使用 bcrypt， strength=10
    }

    public UserDetails getUserLoginInfo(String username) {
        String salt = "123456ef";
        /**
         * @todo 从数据库或者缓存中取出jwt token生成时用的salt
         * salt = redisTemplate.opsForValue().get("token:"+username);
         */
        UserDetails user = loadUserByUsername(username);
        //将salt放到password字段返回
        return User.builder().username(user.getUsername()).password(salt).authorities(user.getAuthorities()).build();
    }

    public String saveUserLoginInfo(UserDetails user) {
        String salt = "123456ef"; //BCrypt.gensalt();  正式开发时可以调用该方法实时生成加密的salt
        /**
         * @todo 将salt保存到数据库或者缓存中
         * redisTemplate.opsForValue().set("token:"+username, salt, 3600, TimeUnit.SECONDS);
         */
        Algorithm algorithm = Algorithm.HMAC256(salt);
        Date date = new Date(System.currentTimeMillis() + 3600 * 1000);  //设置1小时后过期
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(date)
                .withIssuedAt(new Date())
                .sign(algorithm);
    }

    /**
     * 实现 {@link UserDetailsService} 就只需要重写一个方法，在该方法中返回对应的用户信息。
     *
     * @param username 用户名
     * @return 用户信息
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return User.builder().username("Jack").password(passwordEncoder.encode("jack-password")).roles("USER").build();
    }

    public void createUser(String username, String password) {
        String encryptPwd = passwordEncoder.encode(password);
        /**
         * @todo 保存用户名和加密后密码到数据库
         */
    }

    public void deleteUserLoginInfo(String username) {
        /**
         * @todo 清除数据库或者缓存中登录salt
         */
    }
}

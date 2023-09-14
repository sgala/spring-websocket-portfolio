/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.samples.portfolio.config;

import org.springframework.context.annotation.Bean;
import jakarta.servlet.annotation.WebListener;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;

/**
 * Customizes Spring Security configuration.
 * @author Rob Winch
 */
@EnableWebSecurity
@Configuration
public class WebSecurityConfig {

	@Bean(name = "mvcHandlerMappingIntrospector")
	public HandlerMappingIntrospector mvcHandlerMappingIntrospector() {
		return new HandlerMappingIntrospector();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			.csrf().disable();  // Refactor login form
		http.headers().frameOptions().disable()
				.httpStrictTransportSecurity().disable();

			// See https://jira.springsource.org/browse/SPR-11496
		http
			.headers(headers -> headers.addHeaderWriter(
				new XFrameOptionsHeaderWriter(
						XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN)));

		http
			.authorizeHttpRequests(requests -> requests
					.requestMatchers("/static/**").permitAll()
					.requestMatchers("/webjars/**").permitAll()
					.anyRequest().authenticated()
				)
				.formLogin(form -> form.loginPage("/login.html").permitAll() )
				.logout( logout -> logout.permitAll() );
		return http.build();
	}

	@Bean
	public InMemoryUserDetailsManager userDetailsService() {
		PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

		UserDetails user1 = User.withDefaultPasswordEncoder()
				.username("fabrice")
				.password("fab123")
				.roles("USER")
				.build();
		UserDetails user2 = User.withDefaultPasswordEncoder()
				.username("paulson")
				.password("bond")
				.roles("ADMIN","USER")
				.build();
		return new InMemoryUserDetailsManager(user1,user2);
	}

}
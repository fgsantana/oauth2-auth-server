package com.fgsantana.oauth2authserver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import com.fgsantana.oauth2authserver.security.AuthProperties;

import javax.annotation.PostConstruct;

@SpringBootApplication
public class Oauth2AuthServerApplication {
	@Autowired
	AuthProperties properties;

	public static void main(String[] args) {
		SpringApplication.run(Oauth2AuthServerApplication.class, args);
	}


}

package org.example.owasp;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

	@Bean
	public OpenAPI owaspReviewOpenApi() {
		return new OpenAPI().info(new Info()
				.title("Spring Boot AI OWASP Review Agent")
				.description("Submit a repository snapshot and get back OWASP Top 10:2025 findings.")
				.version("0.0.1"));
	}

}

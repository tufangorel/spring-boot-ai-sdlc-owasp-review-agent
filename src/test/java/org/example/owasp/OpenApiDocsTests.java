package org.example.owasp;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "spring.ai.openai.api-key=test-key")
@AutoConfigureMockMvc
class OpenApiDocsTests {

	@Autowired
	private MockMvc mockMvc;

	@Test
	void documentsOwaspReviewEndpoints() throws Exception {
		mockMvc.perform(get("/v3/api-docs"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.info.title").value("Spring Boot AI OWASP Review Agent"))
				.andExpect(jsonPath("$.info.version").value("0.0.1"))
				.andExpect(jsonPath("$.paths['/api/owasp-reviews'].post.summary").value("Review repository files"))
				.andExpect(jsonPath("$.paths['/api/owasp-reviews'].post.tags[0]").value("OWASP reviews"))
				.andExpect(jsonPath("$.paths['/api/owasp-reviews/archive'].post.summary").value("Review a zip archive"))
				.andExpect(jsonPath("$.paths['/api/owasp-reviews/archive'].post.requestBody.content['multipart/form-data'].schema.properties.archive.format")
						.value("binary"));
	}

}

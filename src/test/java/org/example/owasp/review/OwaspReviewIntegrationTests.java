package org.example.owasp.review;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "spring.ai.openai.api-key=test-key")
@AutoConfigureMockMvc
class OwaspReviewIntegrationTests {

	private static final String REPLY = """
			{
			  "summary": "Missing access check",
			  "verdict": "APPROVE",
			  "findings": [
			    {
			      "file": "src/OrderController.java",
			      "line": 1,
			      "owaspId": "A01:2025",
			      "severity": "CRITICAL",
			      "message": "The order id is taken from the caller with no ownership check",
			      "suggestion": "Authorize the caller against the order before returning it"
			    }
			  ]
			}
			""";

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private StubChatModel chatModel;

	@BeforeEach
	void clearPrompts() {
		chatModel.prompts().clear();
	}

	@Test
	void reviewsRepositoryJsonEndToEnd() throws Exception {
		mockMvc.perform(post("/api/owasp-reviews")
						.contentType(MediaType.APPLICATION_JSON)
						.content("""
								{"repositoryName":"billing","context":"Orders API","files":[{"path":"src/OrderController.java","content":"class OrderController {}"}]}
								"""))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.verdict").value("REQUEST_CHANGES"))
				.andExpect(jsonPath("$.findings[0].owaspId").value("A01:2025"))
				.andExpect(jsonPath("$.findings[0].suggestion").value("Authorize the caller against the order before returning it"));

		assertThat(chatModel.lastPrompt().getUserMessage().getText())
				.contains("Repository: billing")
				.contains("class OrderController {}");
	}

	@Test
	void reviewsAZipEndToEnd() throws Exception {
		MockMultipartFile archive = new MockMultipartFile("archive", "billing.zip", "application/zip", zip());

		mockMvc.perform(multipart("/api/owasp-reviews/archive").file(archive))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.verdict").value("REQUEST_CHANGES"))
				.andExpect(jsonPath("$.findings[0].file").value("src/OrderController.java"));

		assertThat(chatModel.lastPrompt().getUserMessage().getText()).contains("Repository: billing");
	}

	@Test
	void rejectsPathTraversalWithoutCallingTheModel() throws Exception {
		mockMvc.perform(post("/api/owasp-reviews")
						.contentType(MediaType.APPLICATION_JSON)
						.content("""
								{"repositoryName":"billing","files":[{"path":"../secret.java","content":"class Secret {}"}]}
								"""))
				.andExpect(status().isBadRequest());

		assertThat(chatModel.prompts()).isEmpty();
	}

	private static byte[] zip() throws Exception {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try (ZipOutputStream zip = new ZipOutputStream(out)) {
			zip.putNextEntry(new ZipEntry("src/OrderController.java"));
			zip.write("class OrderController {}".getBytes(StandardCharsets.UTF_8));
			zip.closeEntry();
			zip.putNextEntry(new ZipEntry("target/classes/OrderController.class"));
			zip.write(new byte[] { 0, 1, 2 });
			zip.closeEntry();
		}
		return out.toByteArray();
	}

	@TestConfiguration
	static class StubChatModelConfig {

		@Bean
		@Primary
		StubChatModel stubChatModel() {
			return new StubChatModel(REPLY);
		}

	}

}

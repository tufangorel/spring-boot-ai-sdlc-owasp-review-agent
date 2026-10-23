package org.example.owasp.review;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMultipartHttpServletRequestBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(OwaspReviewController.class)
class OwaspReviewControllerTests {

	private static final OwaspReviewResult RESULT = new OwaspReviewResult("Missing access check",
			OwaspReviewResult.Verdict.REQUEST_CHANGES,
			List.of(new OwaspReviewResult.Finding("src/OrderController.java", 1, "A01:2025",
					OwaspReviewResult.Severity.CRITICAL, "No ownership check", "Authorize the caller")));

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private OwaspReviewAgent agent;

	@MockitoBean
	private RepositorySubmission submission;

	@MockitoBean
	private RepositoryArchiveReader archiveReader;

	@Test
	void reviewsRepositoryJson() throws Exception {
		OwaspReviewRequest request = new OwaspReviewRequest("billing", "Orders API",
				List.of(new RepositoryFile("src/OrderController.java", "class OrderController {}")));
		given(submission.prepare(request)).willReturn(request);
		given(agent.review(request)).willReturn(RESULT);

		mockMvc.perform(post("/api/owasp-reviews")
						.contentType(MediaType.APPLICATION_JSON)
						.content("""
								{"repositoryName":"billing","context":"Orders API","files":[{"path":"src/OrderController.java","content":"class OrderController {}"}]}
								"""))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.verdict").value("REQUEST_CHANGES"))
				.andExpect(jsonPath("$.findings[0].owaspId").value("A01:2025"))
				.andExpect(jsonPath("$.findings[0].severity").value("CRITICAL"))
				.andExpect(jsonPath("$.findings[0].file").value("src/OrderController.java"))
				.andExpect(jsonPath("$.findings[0].suggestion").value("Authorize the caller"));

		verify(agent).review(request);
	}

	@Test
	void rejectsARepositoryWithoutFiles() throws Exception {
		mockMvc.perform(post("/api/owasp-reviews")
						.contentType(MediaType.APPLICATION_JSON)
						.content("""
								{"repositoryName":"billing","files":[]}
								"""))
				.andExpect(status().isBadRequest());

		verifyNoInteractions(agent, submission, archiveReader);
	}

	@Test
	void reviewsAZipAndUsesItsFileName() throws Exception {
		List<RepositoryFile> files = List.of(new RepositoryFile("src/OrderController.java", "class OrderController {}"));
		OwaspReviewRequest prepared = new OwaspReviewRequest("billing", "Orders API", files);
		given(archiveReader.read(any())).willReturn(files);
		given(submission.prepare(any())).willReturn(prepared);
		given(agent.review(prepared)).willReturn(RESULT);
		MockMultipartFile archive = new MockMultipartFile("archive", "billing.zip", "application/zip",
				"zip".getBytes(StandardCharsets.UTF_8));

		mockMvc.perform(multipart("/api/owasp-reviews/archive").file(archive).param("context", "Orders API"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.findings[0].severity").value("CRITICAL"));

		ArgumentCaptor<OwaspReviewRequest> captor = ArgumentCaptor.forClass(OwaspReviewRequest.class);
		verify(submission).prepare(captor.capture());
		assertThat(captor.getValue().repositoryName()).isEqualTo("billing");
		assertThat(captor.getValue().context()).isEqualTo("Orders API");
		assertThat(captor.getValue().files()).isEqualTo(files);
	}

	@Test
	void prefersTheRequestedRepositoryName() throws Exception {
		assertThat(archiveRepositoryName("billing.zip", " payments ")).isEqualTo("payments");
	}

	@ParameterizedTest
	@CsvSource({
			"'', archive",
			".zip, archive",
			"BILLING.ZIP, BILLING",
			"snapshot.tar, snapshot.tar",
			"uploads/orders.zip, orders" })
	void derivesTheRepositoryNameFromTheArchiveFileName(String filename, String expected) throws Exception {
		assertThat(archiveRepositoryName(filename, null)).isEqualTo(expected);
	}

	@Test
	void rejectsAnEmptyArchive() throws Exception {
		MockMultipartFile archive = new MockMultipartFile("archive", "billing.zip", "application/zip", new byte[0]);

		mockMvc.perform(multipart("/api/owasp-reviews/archive").file(archive))
				.andExpect(status().isBadRequest());

		verifyNoInteractions(agent, submission, archiveReader);
	}

	private String archiveRepositoryName(String filename, String repositoryName) throws Exception {
		List<RepositoryFile> files = List.of(new RepositoryFile("src/OrderController.java", "class OrderController {}"));
		given(archiveReader.read(any())).willReturn(files);
		given(submission.prepare(any())).willAnswer(invocation -> invocation.getArgument(0));
		given(agent.review(any())).willReturn(RESULT);
		MockMultipartFile archive = new MockMultipartFile("archive", filename, "application/zip",
				"zip".getBytes(StandardCharsets.UTF_8));
		MockMultipartHttpServletRequestBuilder request = multipart("/api/owasp-reviews/archive").file(archive);
		if (repositoryName != null) {
			request.param("repositoryName", repositoryName);
		}

		mockMvc.perform(request).andExpect(status().isOk());

		ArgumentCaptor<OwaspReviewRequest> captor = ArgumentCaptor.forClass(OwaspReviewRequest.class);
		verify(submission).prepare(captor.capture());
		return captor.getValue().repositoryName();
	}

}

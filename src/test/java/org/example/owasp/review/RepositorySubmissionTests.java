package org.example.owasp.review;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RepositorySubmissionTests {

	private final RepositorySubmission submission = new RepositorySubmission(new OwaspReviewProperties());

	@Test
	void normalizesPathsAndKeepsContext() {
		OwaspReviewRequest prepared = submission.prepare(new OwaspReviewRequest(" billing ", "Orders API",
				List.of(new RepositoryFile("src\\OrderController.java", "class OrderController {}"))));

		assertThat(prepared.repositoryName()).isEqualTo("billing");
		assertThat(prepared.context()).isEqualTo("Orders API");
		assertThat(prepared.files()).containsExactly(new RepositoryFile("src/OrderController.java", "class OrderController {}"));
	}

	@Test
	void rejectsPathTraversalDuplicateAndAbsolutePaths() {
		assertThatThrownBy(() -> submission.prepare(request("../secret.java")))
				.isInstanceOf(ResponseStatusException.class)
				.extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
				.isEqualTo(HttpStatus.BAD_REQUEST);

		assertThatThrownBy(() -> submission.prepare(request("C:/secret.java")))
				.isInstanceOf(ResponseStatusException.class);

		assertThatThrownBy(() -> submission.prepare(new OwaspReviewRequest("billing", null, List.of(
				new RepositoryFile("src/A.java", "class A {}"),
				new RepositoryFile("src\\A.java", "class A {}")))))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("Duplicate file path");
	}

	@Test
	void rejectsTooManyFiles() {
		OwaspReviewProperties properties = new OwaspReviewProperties();
		properties.setMaxFiles(1);
		RepositorySubmission limited = new RepositorySubmission(properties);

		assertThatThrownBy(() -> limited.prepare(new OwaspReviewRequest("billing", null, List.of(
				new RepositoryFile("A.java", "class A {}"),
				new RepositoryFile("B.java", "class B {}")))))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("more than 1 files");
	}

	private static OwaspReviewRequest request(String path) {
		return new OwaspReviewRequest("billing", null, List.of(new RepositoryFile(path, "class A {}")));
	}

}

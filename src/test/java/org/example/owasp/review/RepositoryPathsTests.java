package org.example.owasp.review;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.web.server.ResponseStatusException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RepositoryPathsTests {

	@Test
	void normalizesSeparatorsAndSurroundingSpace() {
		assertThat(RepositoryPaths.normalize(" src\\main\\App.java ")).isEqualTo("src/main/App.java");
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = "   ")
	void requiresAPath(String path) {
		assertThatThrownBy(() -> RepositoryPaths.normalize(path))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("File path is required");
	}

	@ParameterizedTest
	@ValueSource(strings = { "/etc/passwd", "\\Windows\\win.ini", "C:/secret.java", "d:\\secret.java" })
	void rejectsAbsolutePaths(String path) {
		assertThatThrownBy(() -> RepositoryPaths.normalize(path))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("File path must be relative");
	}

	@ParameterizedTest
	@ValueSource(strings = { "src/\0App.java", "src//App.java", "src/./App.java", "src/../App.java" })
	void rejectsInvalidSegments(String path) {
		assertThatThrownBy(() -> RepositoryPaths.normalize(path))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("File path is invalid");
	}

}

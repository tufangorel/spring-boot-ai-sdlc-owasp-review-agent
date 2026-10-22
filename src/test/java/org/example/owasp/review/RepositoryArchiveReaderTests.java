package org.example.owasp.review;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RepositoryArchiveReaderTests {

	private final RepositoryArchiveReader reader = new RepositoryArchiveReader(new OwaspReviewProperties());

	@Test
	void readsSourceAndSkipsBuildOutput() throws IOException {
		byte[] zip = zip(
				entry("src/OrderController.java", "class OrderController {}"),
				entry("pom.xml", "<project/>"),
				entry("target/classes/OrderController.class", "not really a class"),
				entry("Dockerfile", "FROM eclipse-temurin:25"));

		List<RepositoryFile> files = reader.read(new ByteArrayInputStream(zip));

		assertThat(files).extracting(RepositoryFile::path)
				.containsExactly("src/OrderController.java", "pom.xml", "Dockerfile");
	}

	@Test
	void rejectsZipSlipAndNonZipBytes() {
		assertThatThrownBy(() -> reader.read(new ByteArrayInputStream(zip(entry("../Evil.java", "class Evil {}")))))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("Archive entry path is invalid");

		assertThatThrownBy(() -> reader.read(new ByteArrayInputStream("not a zip".getBytes(StandardCharsets.UTF_8))))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("not a zip file");
	}

	@Test
	void rejectsAnArchiveWithNoReviewableSource() {
		assertThatThrownBy(() -> reader.read(new ByteArrayInputStream(
				zip(entry("target/classes/App.class", "binary")))))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("no reviewable source");
	}

	private static byte[] zip(ZipPiece... pieces) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try (ZipOutputStream zip = new ZipOutputStream(out)) {
			for (ZipPiece piece : pieces) {
				zip.putNextEntry(new ZipEntry(piece.name()));
				zip.write(piece.bytes());
				zip.closeEntry();
			}
		}
		return out.toByteArray();
	}

	private static ZipPiece entry(String name, String content) {
		return new ZipPiece(name, content.getBytes(StandardCharsets.UTF_8));
	}

	private record ZipPiece(String name, byte[] bytes) {
	}

}

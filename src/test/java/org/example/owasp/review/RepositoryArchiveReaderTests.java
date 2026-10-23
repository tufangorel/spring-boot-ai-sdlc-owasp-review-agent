package org.example.owasp.review;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.zip.CRC32;
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

	@Test
	void skipsDirectoriesBinaryFilesBlankFilesAndUnknownNames() throws IOException {
		byte[] zip = zip(
				entry("src/", ""),
				entry("src/OrderController.java", "class OrderController {}"),
				new ZipPiece("src/Logo.java", new byte[] { 'a', 0, 'b' }),
				entry("src/Empty.java", "   "),
				entry("README", "no extension"),
				entry("src/notes.", "trailing dot"));

		List<RepositoryFile> files = reader.read(new ByteArrayInputStream(zip));

		assertThat(files).extracting(RepositoryFile::path).containsExactly("src/OrderController.java");
	}

	@Test
	void rejectsAnArchiveWithTooManyEntries() {
		OwaspReviewProperties properties = new OwaspReviewProperties();
		properties.setMaxArchiveEntries(1);

		assertThatThrownBy(() -> new RepositoryArchiveReader(properties).read(new ByteArrayInputStream(
				zip(entry("A.java", "class A {}"), entry("B.java", "class B {}")))))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("too many entries");
	}

	@Test
	void rejectsAnArchiveWithTooManyReviewableFiles() {
		OwaspReviewProperties properties = new OwaspReviewProperties();
		properties.setMaxFiles(1);

		assertThatThrownBy(() -> new RepositoryArchiveReader(properties).read(new ByteArrayInputStream(
				zip(entry("A.java", "class A {}"), entry("B.java", "class B {}")))))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("more than 1 reviewable files");
	}

	@Test
	void rejectsAnEntryWhoseDeclaredSizeIsTooLarge() {
		OwaspReviewProperties properties = new OwaspReviewProperties();
		properties.setMaxArchiveBytes(10);

		assertThatThrownBy(() -> new RepositoryArchiveReader(properties).read(new ByteArrayInputStream(
				storedZip("A.java", "class A { int value; }"))))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("maximum review size");
	}

	@Test
	void rejectsAnArchiveWhoseEntriesTogetherAreTooLarge() {
		OwaspReviewProperties properties = new OwaspReviewProperties();
		properties.setMaxArchiveBytes(15);

		assertThatThrownBy(() -> new RepositoryArchiveReader(properties).read(new ByteArrayInputStream(
				zip(entry("A.java", "class A {}"), entry("B.java", "class B {}")))))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("Archive exceeds the maximum review size");
	}

	@Test
	void rejectsAFileLargerThanTheFileLimit() {
		OwaspReviewProperties properties = new OwaspReviewProperties();
		properties.setMaxFileCharacters(5);

		assertThatThrownBy(() -> new RepositoryArchiveReader(properties).read(new ByteArrayInputStream(
				zip(entry("A.java", "class A {}")))))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("A file exceeds the maximum review size");
	}

	@Test
	void rejectsCorruptZipData() throws IOException {
		byte[] zip = zip(entry("A.java", "class A {}"));
		int nameLength = (zip[26] & 0xFF) | (zip[27] & 0xFF) << 8;
		int extraLength = (zip[28] & 0xFF) | (zip[29] & 0xFF) << 8;
		zip[30 + nameLength + extraLength] = (byte) 0xFF;

		assertThatThrownBy(() -> reader.read(new ByteArrayInputStream(zip)))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("not a zip file");
	}

	@Test
	void rejectsShortOrWrongMagicBytes() {
		assertThatThrownBy(() -> reader.read(new ByteArrayInputStream("PK".getBytes(StandardCharsets.UTF_8))))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("not a zip file");

		assertThatThrownBy(() -> reader.read(new ByteArrayInputStream("PXzz".getBytes(StandardCharsets.UTF_8))))
				.isInstanceOf(ResponseStatusException.class)
				.hasMessageContaining("not a zip file");
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

	private static byte[] storedZip(String name, String content) throws IOException {
		byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
		CRC32 crc = new CRC32();
		crc.update(bytes);
		ZipEntry entry = new ZipEntry(name);
		entry.setMethod(ZipEntry.STORED);
		entry.setSize(bytes.length);
		entry.setCompressedSize(bytes.length);
		entry.setCrc(crc.getValue());
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try (ZipOutputStream zip = new ZipOutputStream(out)) {
			zip.putNextEntry(entry);
			zip.write(bytes);
			zip.closeEntry();
		}
		return out.toByteArray();
	}

	private static ZipPiece entry(String name, String content) {
		return new ZipPiece(name, content.getBytes(StandardCharsets.UTF_8));
	}

	private record ZipPiece(String name, byte[] bytes) {
	}

}

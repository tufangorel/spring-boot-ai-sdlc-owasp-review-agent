package org.example.owasp.review;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

@Component
public class RepositoryArchiveReader {

	private static final Set<String> SKIPPED_DIRECTORIES = Set.of(
			"target", "build", "out", "bin", "dist", ".git", ".gradle", ".idea", "node_modules");

	private static final Set<String> EXTENSIONS = Set.of(
			"java", "kt", "kts", "groovy", "gradle", "xml", "yml", "yaml", "properties",
			"json", "html", "js", "jsx", "ts", "tsx", "jsp", "ftl", "md", "txt", "cfg",
			"conf", "ini", "toml");

	private static final Set<String> EXTENSIONLESS_NAMES = Set.of(
			"Dockerfile", "Containerfile", "Jenkinsfile", "Makefile");

	private final OwaspReviewProperties properties;

	public RepositoryArchiveReader(OwaspReviewProperties properties) {
		this.properties = properties;
	}

	public List<RepositoryFile> read(InputStream input) throws IOException {
		List<RepositoryFile> files = new ArrayList<>();
		long bytesRead = 0;
		int entries = 0;
		PushbackInputStream checked = requireZip(input);
		try (ZipInputStream zip = new ZipInputStream(checked, StandardCharsets.UTF_8)) {
			ZipEntry entry;
			while ((entry = zip.getNextEntry()) != null) {
				entries++;
				if (entries > properties.getMaxArchiveEntries()) {
					throw badRequest("Archive has too many entries");
				}
				if (entry.isDirectory()) {
					continue;
				}
				rejectHugeDeclaredSize(entry);
				String path = entryPath(entry.getName());
				byte[] bytes = readEntry(zip);
				bytesRead += bytes.length;
				if (bytesRead > properties.getMaxArchiveBytes()) {
					throw badRequest("Archive exceeds the maximum review size");
				}
				if (!isReviewable(path) || isBinary(bytes)) {
					continue;
				}
				String content = new String(bytes, StandardCharsets.UTF_8);
				if (content.isBlank()) {
					continue;
				}
				files.add(new RepositoryFile(path, content));
				if (files.size() > properties.getMaxFiles()) {
					throw badRequest("Archive contains more than " + properties.getMaxFiles() + " reviewable files");
				}
			}
		}
		catch (ZipException ex) {
			throw badRequest("Archive is not a zip file");
		}
		if (files.isEmpty()) {
			throw badRequest("Archive contains no reviewable source files");
		}
		return List.copyOf(files);
	}

	private static PushbackInputStream requireZip(InputStream input) throws IOException {
		PushbackInputStream checked = new PushbackInputStream(input, 4);
		byte[] magic = checked.readNBytes(4);
		if (magic.length < 4 || magic[0] != 'P' || magic[1] != 'K') {
			checked.close();
			throw badRequest("Archive is not a zip file");
		}
		checked.unread(magic);
		return checked;
	}

	private void rejectHugeDeclaredSize(ZipEntry entry) {
		if (entry.getSize() > properties.getMaxArchiveBytes()) {
			throw badRequest("Archive exceeds the maximum review size");
		}
	}

	private String entryPath(String name) {
		try {
			return RepositoryPaths.normalize(name);
		}
		catch (ResponseStatusException ex) {
			throw badRequest("Archive entry path is invalid");
		}
	}

	private byte[] readEntry(ZipInputStream zip) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		byte[] buffer = new byte[8192];
		int read;
		int total = 0;
		int maxBytes = properties.getMaxFileCharacters();
		while ((read = zip.read(buffer)) >= 0) {
			total += read;
			if (total > maxBytes) {
				throw badRequest("A file exceeds the maximum review size");
			}
			out.write(buffer, 0, read);
		}
		return out.toByteArray();
	}

	private static boolean isReviewable(String path) {
		String[] segments = path.split("/");
		for (int i = 0; i < segments.length - 1; i++) {
			if (SKIPPED_DIRECTORIES.contains(segments[i])) {
				return false;
			}
		}
		String fileName = segments[segments.length - 1];
		if (EXTENSIONLESS_NAMES.contains(fileName)) {
			return true;
		}
		int dot = fileName.lastIndexOf('.');
		if (dot < 0 || dot == fileName.length() - 1) {
			return false;
		}
		return EXTENSIONS.contains(fileName.substring(dot + 1).toLowerCase(Locale.ROOT));
	}

	private static boolean isBinary(byte[] bytes) {
		for (byte value : bytes) {
			if (value == 0) {
				return true;
			}
		}
		return false;
	}

	private static ResponseStatusException badRequest(String message) {
		return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
	}

}

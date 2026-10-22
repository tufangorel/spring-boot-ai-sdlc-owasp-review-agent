package org.example.owasp.review;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

final class RepositoryPaths {

	private RepositoryPaths() {
	}

	static String normalize(String raw) {
		if (raw == null || raw.isBlank()) {
			throw invalid("File path is required");
		}
		if (raw.indexOf('\0') >= 0) {
			throw invalid("File path is invalid");
		}
		String path = raw.replace('\\', '/').trim();
		if (path.startsWith("/") || path.matches("^[A-Za-z]:.*")) {
			throw invalid("File path must be relative");
		}
		String[] parts = path.split("/");
		for (String part : parts) {
			if (part.isEmpty() || ".".equals(part) || "..".equals(part)) {
				throw invalid("File path is invalid");
			}
		}
		return String.join("/", parts);
	}

	private static ResponseStatusException invalid(String message) {
		return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
	}

}

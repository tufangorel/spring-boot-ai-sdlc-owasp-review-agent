package org.example.owasp.review;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

@Component
public class RepositorySubmission {

	private final OwaspReviewProperties properties;

	public RepositorySubmission(OwaspReviewProperties properties) {
		this.properties = properties;
	}

	public OwaspReviewRequest prepare(OwaspReviewRequest request) {
		if (request.repositoryName() == null || request.repositoryName().isBlank()) {
			throw badRequest("Repository name is required");
		}
		List<RepositoryFile> files = request.files();
		if (files == null || files.isEmpty()) {
			throw badRequest("At least one file is required");
		}
		if (files.size() > properties.getMaxFiles()) {
			throw badRequest("Repository contains more than " + properties.getMaxFiles() + " files");
		}

		Map<String, RepositoryFile> unique = new LinkedHashMap<>();
		int total = 0;
		for (RepositoryFile file : files) {
			String path = RepositoryPaths.normalize(file.path());
			if (unique.containsKey(path)) {
				throw badRequest("Duplicate file path: " + path);
			}
			String content = file.content();
			if (content == null || content.isBlank()) {
				throw badRequest("File is empty: " + path);
			}
			if (content.length() > properties.getMaxFileCharacters()) {
				throw badRequest("File exceeds the maximum review size: " + path);
			}
			total += content.length();
			if (total > properties.getMaxTotalCharacters()) {
				throw badRequest("Repository exceeds the maximum review size");
			}
			unique.put(path, new RepositoryFile(path, content));
		}
		return new OwaspReviewRequest(request.repositoryName().trim(), request.context(),
				List.copyOf(new ArrayList<>(unique.values())));
	}

	private static ResponseStatusException badRequest(String message) {
		return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
	}

}

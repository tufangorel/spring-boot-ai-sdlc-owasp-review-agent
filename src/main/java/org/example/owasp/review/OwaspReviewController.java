package org.example.owasp.review;

import java.io.IOException;
import java.util.Locale;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/owasp-reviews")
@Tag(name = "OWASP reviews", description = "OWASP Top 10:2025 review of a repository snapshot")
public class OwaspReviewController {

	private final OwaspReviewAgent agent;

	private final RepositorySubmission submission;

	private final RepositoryArchiveReader archiveReader;

	public OwaspReviewController(OwaspReviewAgent agent, RepositorySubmission submission,
			RepositoryArchiveReader archiveReader) {
		this.agent = agent;
		this.submission = submission;
		this.archiveReader = archiveReader;
	}

	@Operation(summary = "Review repository files",
			description = "Reviews source files sent as JSON. The service does not clone a remote repository or run a build.")
	@PostMapping
	public OwaspReviewResult review(@Valid @RequestBody OwaspReviewRequest request) {
		return agent.review(submission.prepare(request));
	}

	@Operation(summary = "Review a zip archive",
			description = "Reviews source files inside a zip archive. Build output, dependency caches, and binary files are skipped.")
	@PostMapping(path = "/archive", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
	public OwaspReviewResult reviewArchive(
			@RequestPart("archive") MultipartFile archive,
			@RequestParam(required = false) String repositoryName,
			@RequestParam(required = false) String context) throws IOException {
		if (archive == null || archive.isEmpty()) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Archive is empty");
		}
		OwaspReviewRequest request = new OwaspReviewRequest(archiveRepositoryName(repositoryName, archive), context,
				archiveReader.read(archive.getInputStream()));
		return agent.review(submission.prepare(request));
	}

	private static String archiveRepositoryName(String requested, MultipartFile archive) {
		if (StringUtils.hasText(requested)) {
			return requested.trim();
		}
		String filename = StringUtils.getFilename(archive.getOriginalFilename());
		if (!StringUtils.hasText(filename)) {
			return "archive";
		}
		if (filename.toLowerCase(Locale.ROOT).endsWith(".zip")) {
			filename = filename.substring(0, filename.length() - 4);
		}
		return filename.isBlank() ? "archive" : filename;
	}

}

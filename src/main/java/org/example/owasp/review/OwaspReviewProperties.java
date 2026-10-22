package org.example.owasp.review;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "owasp.review")
public class OwaspReviewProperties {

	private int maxFiles = 40;

	private int maxFileCharacters = 100_000;

	private int maxTotalCharacters = 400_000;

	private int batchCharacters = 80_000;

	private long maxArchiveBytes = 8_000_000;

	private int maxArchiveEntries = 1_000;

	public int getMaxFiles() {
		return maxFiles;
	}

	public void setMaxFiles(int maxFiles) {
		this.maxFiles = maxFiles;
	}

	public int getMaxFileCharacters() {
		return maxFileCharacters;
	}

	public void setMaxFileCharacters(int maxFileCharacters) {
		this.maxFileCharacters = maxFileCharacters;
	}

	public int getMaxTotalCharacters() {
		return maxTotalCharacters;
	}

	public void setMaxTotalCharacters(int maxTotalCharacters) {
		this.maxTotalCharacters = maxTotalCharacters;
	}

	public int getBatchCharacters() {
		return batchCharacters;
	}

	public void setBatchCharacters(int batchCharacters) {
		this.batchCharacters = batchCharacters;
	}

	public long getMaxArchiveBytes() {
		return maxArchiveBytes;
	}

	public void setMaxArchiveBytes(long maxArchiveBytes) {
		this.maxArchiveBytes = maxArchiveBytes;
	}

	public int getMaxArchiveEntries() {
		return maxArchiveEntries;
	}

	public void setMaxArchiveEntries(int maxArchiveEntries) {
		this.maxArchiveEntries = maxArchiveEntries;
	}

}

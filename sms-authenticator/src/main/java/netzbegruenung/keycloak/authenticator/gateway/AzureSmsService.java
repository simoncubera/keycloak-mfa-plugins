/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 * @author Simon Schuhmacher, Cubera Solutions AG
 */

package netzbegruenung.keycloak.authenticator.gateway;

import java.util.Map;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.jboss.logging.Logger;

import jakarta.json.Json;
import jakarta.json.JsonObject;

import java.util.Base64;
import java.util.Locale;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class AzureSmsService implements SmsService {
	private static final Logger logger = Logger.getLogger(AzureSmsService.class);
	private static final Pattern plusPrefixPattern = Pattern.compile("\\+");

	private final String apiUrl;
	private final String apiToken;

	private final String countryCode;
	private final String senderId;

	private final boolean hideResponsePayload;

	AzureSmsService(Map<String, String> config) {
		apiUrl = config.get("apiurl");
		apiToken = config.get("apitoken");

		countryCode = config.getOrDefault("countrycode", "");
		senderId = config.get("senderId");

		hideResponsePayload = Boolean.parseBoolean(config.get("hideResponsePayload"));
	}

	public void send(String phoneNumber, String message) {
		phoneNumber = cleanPhoneNumber(phoneNumber, countryCode);
		HttpRequest request = null;
		HttpClient client = HttpClient.newHttpClient();
		try {
			request = buildRequest(phoneNumber, message);

			HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

			int statusCode = response.statusCode();
			String payload = hideResponsePayload ? "redacted" : "Response: " + response.body();

			if (statusCode >= 200 && statusCode < 300) {
				logger.infof("Sent SMS to %s [%s]", phoneNumber, payload);
			} else {
				logger.errorf("Failed to send message to %s with status code: [%d] and body: [%s]. Validate your config.", phoneNumber, statusCode, payload);
			}
		} catch (Exception e) {
			logger.errorf(e, "Failed to send message to %s with request: %s. Validate your config.", phoneNumber, request != null ? request.toString() : "null");
		}
	}

	private HttpRequest buildRequest(String phoneNumber, String message) throws NoSuchAlgorithmException, InvalidKeyException {
		URI apiUri = URI.create(apiUrl + "/sms?api-version=2021-03-07");

		String contentJsonString = buildJsonContent(phoneNumber, message);
		String contentHash = createSha256(contentJsonString);

		String uriHost = apiUri.getHost();
		String uriPath = apiUri.getPath();
		String uriQuery = apiUri.getQuery();
		String uriPathAndQuery = uriPath + (uriQuery != null ? "?" + uriQuery : "");

		ZonedDateTime currentDateTime = ZonedDateTime.now();
		String timestamp = formatDateToRFC1123(currentDateTime);

		String stringToSign = new StringBuilder()
			.append("POST")
			.append("\n")
			.append(uriPathAndQuery)
			.append("\n")
			.append(timestamp)
			.append(";")
			.append(uriHost)
			.append(";")
			.append(contentHash)
			.toString();

		String signature = createHmacSha256(apiToken, stringToSign);

		return HttpRequest.newBuilder()
			.uri(apiUri)
			.header("x-ms-date", timestamp)
			.header("x-ms-content-sha256", contentHash)
			.header("Content-Type", "application/json")
			.header("Authorization", "HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature=" + signature)
			.POST(HttpRequest.BodyPublishers.ofString(contentJsonString))
			.build();
	}

	private String buildJsonContent(String phoneNumber, String message) {
		JsonObject content = Json.createObjectBuilder()
			.add("from", senderId)
			.add(
				"smsRecipients",
				Json.createArrayBuilder()
					.add(
						Json.createObjectBuilder()
							.add("to", phoneNumber)
					)
			)
			.add("message", message)
			.add(
				"smsSendOptions",
				Json.createObjectBuilder()
					.add("enableDeliveryReport", true)
					.add("tag", "keycloakSmsAuthenticator")
			)
			.build();

		return content.toString();
	}

	private static String createSha256(String input) throws NoSuchAlgorithmException {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		byte[] hashBytes = messageDigest.digest(input.getBytes(StandardCharsets.UTF_8));
		return Base64.getEncoder().encodeToString(hashBytes);
	}

	private static String createHmacSha256(String key, String data) throws NoSuchAlgorithmException, InvalidKeyException {
		Mac mac = Mac.getInstance("HmacSHA256");
		byte[] keyBytes = Base64.getDecoder().decode(key);

		SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "HmacSHA256");

		mac.init(secretKeySpec);
		byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
		return Base64.getEncoder().encodeToString(hmacBytes);
	}

	private static String formatDateToRFC1123(ZonedDateTime zonedDateTime) {
		return DateTimeFormatter.RFC_1123_DATE_TIME
			.withLocale(Locale.US)
			.format(zonedDateTime);
	}

	private static String cleanPhoneNumber(String phoneNumber, String countryCode) {
		/*
		 * This function tries to correct several common user errors. If there is no default country
		 * prefix, this function does not dare to touch the phone number.
		 * https://en.wikipedia.org/wiki/List_of_mobile_telephone_prefixes_by_country
		 */
		if (countryCode == null || countryCode.isEmpty()) {
			logger.infof("Clean phone number: no country code set, return %s", phoneNumber);
			return phoneNumber;
		}
		String country_number = plusPrefixPattern.matcher(countryCode).replaceFirst("");
		// convert 49 to +49
		if (phoneNumber.startsWith(country_number)) {
			phoneNumber = phoneNumber.replaceFirst(country_number, countryCode);
			logger.infof("Clean phone number: convert 49 to +49, set phone number to %s", phoneNumber);
		}
		// convert 0049 to +49
		if (phoneNumber.startsWith("00" + country_number)) {
			phoneNumber = phoneNumber.replaceFirst("00" + country_number, countryCode);
			logger.infof("Clean phone number: convert 0049 to +49, set phone number to %s", phoneNumber);
		}
		// convert +490176 to +49176
		if (phoneNumber.startsWith(countryCode + '0')) {
			phoneNumber = phoneNumber.replaceFirst("\\+" + country_number + '0', countryCode);
			logger.infof("Clean phone number: convert +490176 to +49176, set phone number to %s", phoneNumber);
		}
		// convert 0 to +49
		if (phoneNumber.startsWith("0")) {
			phoneNumber = phoneNumber.replaceFirst("0", countryCode);
			logger.infof("Clean phone number: convert 0 to +49, set phone number to %s", phoneNumber);
		}
		return phoneNumber;
	}
}

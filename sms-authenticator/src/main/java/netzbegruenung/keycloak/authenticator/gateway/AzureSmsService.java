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
import java.util.regex.Pattern;

import org.jboss.logging.Logger;

import com.azure.communication.sms.SmsClient;
import com.azure.communication.sms.SmsClientBuilder;
import com.azure.communication.sms.models.SmsSendOptions;
import com.azure.communication.sms.models.SmsSendResult;
import com.azure.core.credential.AzureKeyCredential;

public class AzureSmsService implements SmsService {
	private static final Logger logger = Logger.getLogger(AzureSmsService.class);
	private static final Pattern plusPrefixPattern = Pattern.compile("\\+");

	private final String apiUrl;
	private final String apiToken;
	private final String countryCode;
	private final String senderId;

	private final AzureKeyCredential azureKeyCredential;
	private final SmsClient smsClient;


	AzureSmsService(Map<String, String> config) {
		apiUrl = config.get("apiurl");
		apiToken = config.get("apitoken");

		countryCode = config.getOrDefault("countrycode", "");
		senderId = config.get("senderId");

		try {
			azureKeyCredential = new AzureKeyCredential(apiToken);
			smsClient = new SmsClientBuilder()
				.endpoint(apiUrl)
				.credential(azureKeyCredential)
				.buildClient();
		} catch (Exception e) {
			logger.errorf("Failed to initialize AzureSmsService. Please make sure the endpoint (SMS API URL) " +
				"and key (API Secret) are in the correct format", e);
			throw e;
		}
	}

	public void send(String phoneNumber, String message) {
		phoneNumber = cleanPhoneNumber(phoneNumber, countryCode);

		SmsSendOptions smsSendOptions = new SmsSendOptions();
		smsSendOptions.setDeliveryReportEnabled(true);
		smsSendOptions.setTag("keycloakSmsAuthenticator");

		try {
			SmsSendResult smsSendResult = smsClient.send(senderId, phoneNumber, message, smsSendOptions);

			if (smsSendResult.isSuccessful()) {
				logger.infof(
					"Successfully sent SMS to: %s messageId: %s statusCode: %d",
					smsSendResult.getTo(),
					smsSendResult.getMessageId(),
					smsSendResult.getHttpStatusCode()
				);
			} else {
				logger.errorf(
					"Failed to send SMS to: %s statusCode: %d errorMessage: %s .",
					smsSendResult.getTo(),
					smsSendResult.getHttpStatusCode(),
					smsSendResult.getErrorMessage()
				);
			}

		} catch (Exception e) {
			logger.errorf(e, "Failed to send message to %s. Make sure your config is correct.", phoneNumber);
		}
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

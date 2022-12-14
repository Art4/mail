<?php

declare(strict_types=1);

/**
 * @copyright Copyright (c) 2022 Richard Steinmetz <richard@steinmetz.cloud>
 *
 * @author Richard Steinmetz <richard@steinmetz.cloud>
 *
 * @license AGPL-3.0-or-later
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

namespace OCA\Mail\Service;

use OCA\Mail\Exception\ServiceException;

class SMimeCertificateService {
	/**
	 * Parse a X509 certificate and extract the email address from its subject.
	 *
	 * @param string $certificate X509 certificate encoded as PEM
	 * @return ?string Email address of the subject or null if it has none
	 *
	 * @throws ServiceException If the certificate can't be parsed
	 */
	public function extractEmailAddress(string $certificate): ?string {
		$certificateData = openssl_x509_parse($certificate);
		if ($certificateData === false) {
			throw new ServiceException('Could not parse certificate');
		}

		return $certificateData['subject']['emailAddress'] ?? null;
	}
}

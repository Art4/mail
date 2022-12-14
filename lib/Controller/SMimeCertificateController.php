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

namespace OCA\Mail\Controller;

use OCA\Mail\Db\SMimeCertificate;
use OCA\Mail\Db\SMimeCertificateMapper;
use OCA\Mail\Service\SMimeCertificateService;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\JSONResponse;
use OCP\IRequest;
use OCP\IUser;
use OCP\Security\ICrypto;

class SMimeCertificateController extends Controller {
	private string $userId;
	private SMimeCertificateService $certificateService;
	private SMimeCertificateMapper $certificateMapper;
	private ICrypto $crypto;

	public function __construct(string $appName,
								IRequest $request,
								string $userId,
								SMimeCertificateService $certificateService,
								SMimeCertificateMapper $certificateMapper,
								ICrypto $crypto) {
		parent::__construct($appName, $request);
		$this->userId = $userId;
		$this->certificateService = $certificateService;
		$this->certificateMapper = $certificateMapper;
		$this->crypto = $crypto;
	}

	/**
	 * @NoAdminRequired
	 * @TrapError
	 * @NoCSRFRequired
	 */
	public function index(): JSONResponse {
		$certificates = $this->certificateMapper->findAll($this->userId);
		return new JSONResponse($certificates);
	}

	/**
	 * @NoAdminRequired
	 * @TrapError
	 * @NoCSRFRequired
	 *
	 * @param string $certificate
	 */
	public function import(string $certificate, ?string $privateKey): JSONResponse {
		$emailAddress = $this->certificateService->extractEmailAddress($certificate);

		$entity = new SMimeCertificate();
		$entity->setUserId($this->userId);
		$entity->setEmailAddress($emailAddress);
		$entity->setCertificate($this->crypto->encrypt($certificate));
		if ($privateKey !== null) {
			$privateKey = $this->crypto->encrypt($privateKey);
			$entity->setPrivateKey($privateKey);
		}
		$this->certificateMapper->insert($entity);

		return new JSONResponse();
	}
}

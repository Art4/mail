<!--
  - @copyright 2018 Christoph Wurst <christoph@winzerhof-wurst.at>
  -
  - @author 2018 Christoph Wurst <christoph@winzerhof-wurst.at>
  -
  - @license AGPL-3.0-or-later
  -
  - This program is free software: you can redistribute it and/or modify
  - it under the terms of the GNU Affero General Public License as
  - published by the Free Software Foundation, either version 3 of the
  - License, or (at your option) any later version.
  -
  - This program is distributed in the hope that it will be useful,
  - but WITHOUT ANY WARRANTY; without even the implied warranty of
  - MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  - GNU Affero General Public License for more details.
  -
  - You should have received a copy of the GNU Affero General Public License
  - along with this program.  If not, see <http://www.gnu.org/licenses/>.
  -->

<template>
	<NcEmptyContent
		:title="error"
		:description="message">
		<p v-if="data && data.debug">
			<a class="button"
				:href="reportUrl"
				target="_blank"
				rel="noopener">{{ t('mail', 'Report this bug') }}</a>
		</p>
	</NcEmptyContent>
</template>

<script>
import { getReportUrl } from '../util/CrashReport'
import NcEmptyContent from '@nextcloud/vue/dist/Components/NcEmptyContent'

export default {
	name: 'Error',
	components: {
		NcEmptyContent,
	},
	props: {
		error: {
			type: String,
			required: true,
		},
		message: {
			type: String,
			required: true,
		},
		data: {
			type: Object,
			default: () => undefined,
		},
	},
	computed: {
		reportUrl() {
			return getReportUrl(this.data)
		},
	},
}
</script>

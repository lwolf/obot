import { ChatService } from '$lib/services';
import type { Version } from '$lib/services/chat/types';
import type { PageLoad } from './$types';
import { redirect } from '@sveltejs/kit';

export const load: PageLoad = async ({ fetch }) => {
	let version: Version = {};
	try {
		version = await ChatService.getVersion({ fetch });
	} catch {
		// default: redirect when version is unreachable
	}
	if (!version.messagePoliciesEnabled) {
		throw redirect(302, '/admin');
	}

	return {};
};

import { handleRouteError } from '$lib/errors';
import { AdminService, ChatService } from '$lib/services';
import type { MessagePolicy } from '$lib/services/admin/types';
import type { Version } from '$lib/services/chat/types';
import { profile } from '$lib/stores';
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

	let messagePolicies: MessagePolicy[] = [];

	try {
		messagePolicies = await AdminService.listMessagePolicies({ fetch });
	} catch (err) {
		handleRouteError(err, '/admin/message-policies', profile.current);
	}

	return {
		messagePolicies
	};
};

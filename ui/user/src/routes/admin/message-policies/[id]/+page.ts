import { handleRouteError } from '$lib/errors';
import { AdminService, ChatService } from '$lib/services';
import type { Version } from '$lib/services/chat/types';
import { profile } from '$lib/stores';
import type { PageLoad } from './$types';
import { redirect } from '@sveltejs/kit';

export const load: PageLoad = async ({ params, fetch }) => {
	let version: Version = {};
	try {
		version = await ChatService.getVersion({ fetch });
	} catch {
		// default: redirect when version is unreachable
	}
	if (!version.messagePoliciesEnabled) {
		throw redirect(302, '/admin');
	}

	const { id } = params;

	let messagePolicy;
	try {
		messagePolicy = await AdminService.getMessagePolicy(id, { fetch });
	} catch (err) {
		handleRouteError(err, `/admin/message-policies/${id}`, profile.current);
	}

	return {
		messagePolicy
	};
};

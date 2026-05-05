import { ChatService, NanobotService } from '$lib/services';
import type { Version } from '$lib/services/chat/types';
import type { PageLoad } from './$types';
import { redirect } from '@sveltejs/kit';

export const ssr = false;

export const load: PageLoad = async ({ fetch }) => {
	let version: Version = { nanobotIntegration: true };
	try {
		version = await ChatService.getVersion({ fetch });
	} catch {
		// assume nanobot integration is enabled when version is unreachable
	}
	if (!version.nanobotIntegration) {
		throw redirect(302, '/');
	}

	const projects = await NanobotService.listProjectsV2({ fetch });
	if (projects.length === 0) {
		const project = await NanobotService.createProjectV2({ displayName: 'New Project' }, { fetch });
		throw redirect(302, `/agent/p/${project.id}`);
	}
	throw redirect(302, `/agent/p/${projects[0].id}`);
};

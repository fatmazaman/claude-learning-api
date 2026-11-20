import type { FastifyInstance, FastifyRequest } from 'fastify';
import { requireAuth, type TokenVerifier } from '../auth';
import type { NotesStore } from '../notes-store';
import { requireScope } from '../scopes';

const noteSchema = {
	type: 'object',
	required: ['id', 'text', 'createdAt'],
	properties: {
		id: { type: 'string' },
		text: { type: 'string' },
		createdAt: { type: 'string' },
	},
} as const;

/** The caller's id. requireAuth has run by now, so a missing user is a wiring bug. */
function subOf(request: FastifyRequest): string {
	if (!request.user) throw new Error('notes route ran without requireAuth');
	return request.user.sub;
}

/**
 * Notes API, the demo resource for scope-based authorization: reading needs `notes:read`,
 * writing needs `notes:write`. Authentication and the scope check run in `onRequest`, before
 * the body is parsed and validated, so a caller who is not allowed in gets 401/403 and never a
 * 400 that describes the schema. The store is shared with the MCP tools, so a note added over
 * MCP shows up here for the same user.
 */
export function registerNotes(
	instance: FastifyInstance,
	verifyToken: TokenVerifier,
	store: NotesStore,
) {
	const authenticate = requireAuth(verifyToken);

	instance.get(
		'/notes',
		{
			onRequest: [authenticate, requireScope('notes:read')],
			schema: { response: { 200: { type: 'array', items: noteSchema } } },
		},
		async (request) => store.list(subOf(request)),
	);

	instance.post<{ Body: { text: string } }>(
		'/notes',
		{
			onRequest: [authenticate, requireScope('notes:write')],
			bodyLimit: 4096,
			schema: {
				body: {
					type: 'object',
					required: ['text'],
					additionalProperties: false,
					properties: { text: { type: 'string', minLength: 1, maxLength: 500 } },
				},
				response: { 201: noteSchema },
			},
		},
		async (request, reply) => {
			const result = store.add(subOf(request), request.body.text);
			if (!result.ok) return reply.code(409).send({ error: 'Note limit reached' });
			return reply.code(201).send(result.note);
		},
	);
}

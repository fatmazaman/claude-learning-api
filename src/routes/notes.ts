import { randomUUID } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { requireAuth, type TokenVerifier } from '../auth';
import { requireScope } from '../scopes';

interface Note {
	id: string;
	text: string;
	createdAt: string;
}

const MAX_NOTES_PER_USER = 100;

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
 * 400 that describes the schema.
 */
export function registerNotes(instance: FastifyInstance, verifyToken: TokenVerifier) {
	// Demo store: in memory, per app instance, gone on restart. Each user only sees their own.
	const notesBySub = new Map<string, Note[]>();
	const authenticate = requireAuth(verifyToken);

	instance.get(
		'/notes',
		{
			onRequest: [authenticate, requireScope('notes:read')],
			schema: { response: { 200: { type: 'array', items: noteSchema } } },
		},
		async (request) => notesBySub.get(subOf(request)) ?? [],
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
			const sub = subOf(request);
			const notes = notesBySub.get(sub) ?? [];
			if (notes.length >= MAX_NOTES_PER_USER) {
				return reply.code(409).send({ error: 'Note limit reached' });
			}
			const note: Note = {
				id: randomUUID(),
				text: request.body.text,
				createdAt: new Date().toISOString(),
			};
			notes.push(note);
			notesBySub.set(sub, notes);
			return reply.code(201).send(note);
		},
	);
}

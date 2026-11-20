import {
	createMcpHandler,
	McpServer,
	requireScopes,
	type AuthInfo,
} from '@modelcontextprotocol/server';
import * as z from 'zod/v4';
import type { NotesStore } from '../notes-store';
import { NOTES_READ, NOTES_WRITE } from './config';

/** The caller's id from the verified token. Fails closed if it is somehow missing. */
function subOf(authInfo: AuthInfo | undefined): string {
	const sub = authInfo?.extra?.sub;
	if (typeof sub !== 'string' || sub === '') throw new Error('No authenticated user.');
	return sub;
}

/**
 * The MCP handler. The factory runs once per HTTP request and builds a fresh server, so no
 * state lives on the instance and nothing can leak between callers: every tool reads the
 * caller's `sub` from that request's `authInfo` and touches only that user's notes.
 *
 * Each tool declares a `scopeChallenge`. The SDK checks it before the tool's input is even
 * validated, and answers a token without the scope with HTTP 403 `insufficient_scope`
 * (`WWW-Authenticate` naming the scope and the metadata URL), never a tool result.
 *
 * No tool makes an outbound request, and the `authInfo` it receives carries no token.
 */
export function createNotesMcpHandler(store: NotesStore) {
	return createMcpHandler(
		({ authInfo }) => {
			const server = new McpServer({ name: 'notes', version: '1.0.0' });

			server.registerTool(
				'list_notes',
				{
					description: "List the signed-in user's notes.",
					annotations: { readOnlyHint: true },
					scopeChallenge: requireScopes(NOTES_READ),
				},
				async () => ({
					content: [{ type: 'text', text: JSON.stringify(store.list(subOf(authInfo)), null, 2) }],
				}),
			);

			server.registerTool(
				'add_note',
				{
					description: 'Add a note for the signed-in user.',
					inputSchema: z.object({ text: z.string().min(1).max(500) }).strict(),
					annotations: { readOnlyHint: false, destructiveHint: false },
					scopeChallenge: requireScopes(NOTES_WRITE),
				},
				async ({ text }) => {
					const result = store.add(subOf(authInfo), text);
					if (!result.ok) {
						return {
							content: [{ type: 'text', text: 'Note limit reached (100 notes per user).' }],
							isError: true,
						};
					}
					return { content: [{ type: 'text', text: JSON.stringify(result.note, null, 2) }] };
				},
			);

			return server;
		},
		// No tool ever changes, so nothing needs `subscriptions/listen`. Left on (default cap 1024),
		// any authenticated caller, even with no scopes, could hold long-lived streams open.
		{ maxSubscriptions: 0 },
	);
}

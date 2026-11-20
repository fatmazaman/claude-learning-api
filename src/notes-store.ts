import { randomUUID } from 'node:crypto';

export interface Note {
	id: string;
	text: string;
	createdAt: string;
}

export const MAX_NOTES_PER_USER = 100;

export type AddNoteResult = { ok: true; note: Note } | { ok: false; reason: 'limit' };

/**
 * The demo resource behind both the REST `/notes` routes and the MCP tools: in memory, gone
 * on restart. Notes are private to the user who owns them, keyed by the token's `sub`.
 * Callers get copies, so nothing outside can mutate the store.
 */
export class NotesStore {
	private readonly bySub = new Map<string, Note[]>();

	list(sub: string): Note[] {
		return (this.bySub.get(sub) ?? []).map((note) => ({ ...note }));
	}

	add(sub: string, text: string): AddNoteResult {
		const notes = this.bySub.get(sub) ?? [];
		if (notes.length >= MAX_NOTES_PER_USER) return { ok: false, reason: 'limit' };
		const note: Note = { id: randomUUID(), text, createdAt: new Date().toISOString() };
		notes.push(note);
		this.bySub.set(sub, notes);
		return { ok: true, note: { ...note } };
	}
}

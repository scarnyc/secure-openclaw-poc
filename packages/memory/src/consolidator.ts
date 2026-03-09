import type { CreateSummary } from "./schema.js";
import type { MemoryStore } from "./store.js";

export interface ConsolidationResult {
	skipped: boolean;
	summaryId?: string;
}

export class Consolidator {
	constructor(private store: MemoryStore) {}

	generateSessionSummary(sessionId: string, project: string): CreateSummary {
		const observations = this.store.getObservationsBySession(sessionId);

		const investigated: string[] = [];
		const learned: string[] = [];
		const completed: string[] = [];
		const nextSteps: string[] = [];
		const observationIds: string[] = [];

		for (const obs of observations) {
			observationIds.push(obs.id);

			switch (obs.type) {
				case "context":
					investigated.push(obs.title);
					break;
				case "learning":
					learned.push(obs.title);
					break;
				case "decision":
					completed.push(obs.title);
					break;
				case "error":
					investigated.push(`Error: ${obs.title}`);
					break;
				case "tool_call":
					completed.push(obs.title);
					break;
			}
		}

		const firstObs = observations[0];
		const lastObs = observations[observations.length - 1];

		return {
			project,
			source: firstObs?.source ?? "developer",
			scope: "session",
			periodStart: firstObs?.createdAt ?? new Date().toISOString(),
			periodEnd: lastObs?.createdAt ?? new Date().toISOString(),
			title: `Session ${sessionId}`,
			investigated,
			learned,
			completed,
			nextSteps,
			observationIds,
		};
	}

	consolidateDay(project: string, range: { start: string; end: string }): ConsolidationResult {
		if (this.store.hasSummaryForPeriod("daily", range)) {
			return { skipped: true };
		}

		const sessionSummaries = this.store.getSummariesByPeriod("session", range);
		if (sessionSummaries.length === 0) {
			return { skipped: true };
		}

		// Merge session summaries, deduplicating items
		const investigated = new Set<string>();
		const learned = new Set<string>();
		const completed = new Set<string>();
		const nextSteps = new Set<string>();
		const allObsIds = new Set<string>();

		for (const summary of sessionSummaries) {
			for (const item of summary.investigated) investigated.add(item);
			for (const item of summary.learned) learned.add(item);
			for (const item of summary.completed) completed.add(item);
			for (const item of summary.nextSteps) nextSteps.add(item);
			for (const id of summary.observationIds) allObsIds.add(id);
		}

		const dailySummary: CreateSummary = {
			project,
			source: sessionSummaries[0].source,
			scope: "daily",
			periodStart: range.start,
			periodEnd: range.end,
			title: `Daily summary: ${new Date(range.start).toISOString().split("T")[0]}`,
			investigated: [...investigated],
			learned: [...learned],
			completed: [...completed],
			nextSteps: [...nextSteps],
			observationIds: [...allObsIds],
		};

		const summaryId = this.store.writeSummary(dailySummary);
		return { skipped: false, summaryId };
	}
}

/**
 * @file OverlapMergingResolver.ts
 * @module @promptwall/engine/graph
 *
 * Implements an overlap-merging {@link GraphResolver} strategy.
 *
 * ── Deduplication logic ────────────────────────────────────────────────────────
 *
 * 1. Collect all candidate nodes from the graph.
 * 2. Group nodes into overlapping spans. Two candidates overlap if:
 *      `startA < endB && startB < endA`
 * 3. Within each overlapping group:
 *      - Select the winning candidate with the highest `confidence` score
 *        (tie-breaker: lowest priority/most severe or stable candidate ID).
 *      - Merge all evidence items from all candidates in the group into the winner's `evidence` array,
 *        deduplicating evidence by evidence `id`.
 *      - Keep the winner's original `location` span and `confidence` intact.
 * 4. Return non-overlapping, deduplicated candidates ordered by `location.start` ascending.
 */

import type { Candidate } from "../candidate/Candidate";
import type { Evidence } from "../candidate/Evidence";
import type { CandidateNode, GraphResolver } from "./CandidateGraph";

export class OverlapMergingResolver implements GraphResolver {
  resolve(nodes: ReadonlyMap<string, CandidateNode>): Candidate[] {
    if (nodes.size === 0) {
      return [];
    }

    const candidates = Array.from(nodes.values()).map((n) => n.candidate);

    // Sort candidates by start position ascending, then length descending
    const sorted = [...candidates].sort((a, b) => {
      if (a.location.start !== b.location.start) {
        return a.location.start - b.location.start;
      }
      return (b.location.end - b.location.start) - (a.location.end - a.location.start);
    });

    // Group overlapping candidates
    const groups: Candidate[][] = [];
    for (const cand of sorted) {
      let mergedIntoExisting = false;
      for (const group of groups) {
        // A candidate overlaps with a group if it overlaps with ANY member of that group
        const overlapsWithGroup = group.some((member) =>
          this.doOverlap(cand.location, member.location)
        );
        if (overlapsWithGroup) {
          group.push(cand);
          mergedIntoExisting = true;
          break;
        }
      }
      if (!mergedIntoExisting) {
        groups.push([cand]);
      }
    }

    // Resolve each group into a single merged candidate
    return groups.map((group) => this.mergeGroup(group));
  }

  private doOverlap(
    locA: { start: number; end: number },
    locB: { start: number; end: number }
  ): boolean {
    return locA.start < locB.end && locB.start < locA.end;
  }

  private mergeGroup(group: Candidate[]): Candidate {
    if (group.length === 1) {
      return group[0]!;
    }

    // Pick winner: highest confidence, then highest severity, then stable id comparison
    const sortedGroup = [...group].sort((a, b) => {
      if (b.confidence !== a.confidence) {
        return b.confidence - a.confidence;
      }
      const sevDiff = severityRank(b.severity) - severityRank(a.severity);
      if (sevDiff !== 0) return sevDiff;
      return a.id.localeCompare(b.id);
    });

    const winner = sortedGroup[0]!;

    // Combine evidence from all candidates in group without duplicating evidence IDs
    const seenEvidenceIds = new Set<string>();
    const combinedEvidence: Evidence[] = [];

    for (const cand of group) {
      for (const ev of cand.evidence) {
        if (!seenEvidenceIds.has(ev.id)) {
          seenEvidenceIds.add(ev.id);
          combinedEvidence.push(ev);
        }
      }
    }

    const mergedCandidate: Candidate = {
      id: winner.id,
      category: winner.category,
      subtype: winner.subtype,
      value: winner.value,
      normalizedValue: winner.normalizedValue,
      location: winner.location,
      confidence: winner.confidence,
      severity: winner.severity,
      detector: winner.detector,
      evidence: combinedEvidence,
      metadata: winner.metadata,
    };

    return mergedCandidate;
  }
}

function severityRank(severity: string): number {
  switch (severity) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}

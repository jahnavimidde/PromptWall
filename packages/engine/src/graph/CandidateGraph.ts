/**
 * @file CandidateGraph.ts
 * @module @promptwall/engine/graph
 *
 * Accumulates candidates from multiple detectors and resolves them into
 * a final, deduplicated set via a pluggable {@link GraphResolver} strategy.
 *
 * Current behaviour (Milestone 1): additive merge with identity resolution.
 * Candidates are stored as nodes in a Map; no edges are built yet.
 *
 * Future milestones will activate the edge-building and resolution hooks marked
 * with `// TODO(milestone-N)` comments throughout this file.
 */

import type { Candidate } from "../candidate/Candidate";

// ── CandidateNode ─────────────────────────────────────────────────────────────

/**
 * A node in the candidate graph.
 *
 * `edges` is a set of candidate IDs whose locations overlap or conflict with
 * this candidate. In Milestone 1, `edges` is always empty. Future milestones
 * will populate edges during overlap detection.
 */
export interface CandidateNode {
  readonly candidate: Candidate;
  /**
   * IDs of candidates that overlap or conflict with this one.
   * Empty in Milestone 1; populated during overlap detection in future milestones.
   */
  readonly edges: ReadonlySet<string>;
}

// ── GraphResolver ─────────────────────────────────────────────────────────────

/**
 * Strategy interface for resolving the candidate graph into a final list.
 *
 * Implement this interface to plug in custom resolution logic:
 * - Prefer the highest-confidence candidate in an overlapping group
 * - Merge evidence arrays from overlapping candidates into a single canonical candidate
 * - Flag conflicting detections for manual review
 * - Suppress low-confidence duplicates
 *
 * The registry ships {@link PassthroughGraphResolver} as the default, which returns
 * all candidates unchanged. Replace it by passing a custom resolver to
 * {@link CandidateGraph}'s constructor.
 *
 * @example Custom resolver (future milestone)
 * ```ts
 * class HighestConfidenceResolver implements GraphResolver {
 *   resolve(nodes: ReadonlyMap<string, CandidateNode>): Candidate[] {
 *     // Group overlapping nodes via edges, pick winner per group
 *     return pickHighestPerGroup(nodes);
 *   }
 * }
 * const graph = new CandidateGraph(new HighestConfidenceResolver());
 * ```
 */
export interface GraphResolver {
  /**
   * Transform the current graph state into the final candidate list.
   *
   * @param nodes - All candidate nodes, keyed by candidate `id`.
   *   Nodes are readonly; the resolver must not mutate them.
   * @returns The resolved, ordered list of candidates to surface to callers.
   */
  resolve(nodes: ReadonlyMap<string, CandidateNode>): Candidate[];
}

// ── PassthroughGraphResolver ──────────────────────────────────────────────────

/**
 * Identity resolver — returns all candidates in insertion order, unchanged.
 * Shipped as the default until a real resolution strategy is configured.
 *
 * No overlap detection, no deduplication, no confidence adjustment.
 */
export class PassthroughGraphResolver implements GraphResolver {
  resolve(nodes: ReadonlyMap<string, CandidateNode>): Candidate[] {
    return Array.from(nodes.values()).map((node) => node.candidate);
  }
}

// ── CandidateGraph ─────────────────────────────────────────────────────────────

/**
 * Accumulates candidates from multiple detectors and resolves them into
 * a final list via the injected {@link GraphResolver}.
 *
 * Lifecycle of a typical detection run:
 * ```
 * const graph = new CandidateGraph();
 * graph.add(resultsFromDetectorA);
 * graph.add(resultsFromDetectorB);
 * const resolved = graph.resolve();  // or graph.merge(resultsFromDetectorC)
 * ```
 *
 * Extension points are marked with `// TODO(milestone-N)` for future work:
 * - Overlap detection: build edges between candidates sharing location ranges.
 * - Evidence aggregation: merge `evidence[]` when candidates share the same entity.
 * - Confidence propagation: update confidence scores based on graph topology.
 * - Conflict resolution: delegate to resolver strategy to pick winners.
 */
export class CandidateGraph {
  /**
   * Internal mutable node map. Exposed to the resolver as a ReadonlyMap
   * to prevent resolver implementations from mutating graph state.
   */
  private readonly nodes = new Map<string, { candidate: Candidate; edges: Set<string> }>();
  private readonly resolver: GraphResolver;

  constructor(resolver: GraphResolver = new PassthroughGraphResolver()) {
    this.resolver = resolver;
  }

  /**
   * Add candidates to the graph. Candidates with duplicate IDs are silently
   * ignored (first-write-wins semantics preserve the originating detector's data).
   *
   * @param candidates - Candidates to insert. Duplicate IDs are skipped.
   */
  add(candidates: readonly Candidate[]): void {
    for (const candidate of candidates) {
      if (!this.nodes.has(candidate.id)) {
        this.nodes.set(candidate.id, {
          candidate,
          // TODO(milestone-2): after insert, run overlap detection against
          // existing nodes and populate edges bidirectionally.
          edges: new Set<string>(),
        });
      }
    }
    // TODO(milestone-2): trigger incremental edge computation after batch insert.
  }

  /**
   * Convenience method: add candidates, then resolve and return the final list.
   * Equivalent to `graph.add(incoming); return graph.resolve();`
   *
   * @param incoming - New candidates to incorporate before resolving.
   */
  merge(incoming: readonly Candidate[]): Candidate[] {
    this.add(incoming);
    return this.resolve();
  }

  /**
   * Resolve the current graph state into a final candidate list.
   * Delegates entirely to the injected {@link GraphResolver}.
   *
   * @returns Final candidates as determined by the resolver strategy.
   */
  resolve(): Candidate[] {
    // TODO(milestone-2): compute overlap/conflict edges here before resolving,
    // so the resolver receives a fully populated graph.
    return this.resolver.resolve(
      // Cast: Map<id, {candidate, edges: Set}> satisfies ReadonlyMap<id, CandidateNode>
      // because Set<string> satisfies ReadonlySet<string>.
      this.nodes as ReadonlyMap<string, CandidateNode>,
    );
  }

  /** Remove all nodes and edges from the graph, resetting to initial state. */
  clear(): void {
    this.nodes.clear();
  }

  /** Number of candidate nodes currently in the graph (before resolution). */
  get size(): number {
    return this.nodes.size;
  }

  /**
   * Check whether a candidate with this `id` exists in the graph.
   * Useful for deduplication guards in higher-level orchestrators.
   */
  has(id: string): boolean {
    return this.nodes.has(id);
  }
}

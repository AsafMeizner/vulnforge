/**
 * Barrel export for VulnForge metrics.
 *
 * Consumed by the integrator from:
 *   - `server/pipeline/orchestrator.ts` (recordStageComplete, recordAIUsage)
 *   - `server/scanner/runner.ts` (recordToolRun wrapper)
 *   - `server/routes/metrics.ts` (getToolMetrics, getPipelineMetrics, getFindingMetrics)
 *   - `server/mcp/tools.ts` (get_tool_metrics MCP tool)
 */
export {
  recordToolRun,
  getToolMetrics,
  getToolMetrics24h,
  getToolMetricsBothWindows,
  getRecentToolRuns,
  __resetToolMetricsMemoryCache,
  __resetToolMetricsSchema,
} from './tool-metrics.js';
export type {
  ToolRunMetrics,
  ToolRollup,
  ToolMetricsSummary,
} from './tool-metrics.js';

export {
  recordStageComplete,
  recordAIUsage,
  getPipelineMetrics,
  listPipelineMetricIds,
  __resetPipelineMetricsSchema,
} from './pipeline-metrics.js';
export type {
  PipelineTier,
  StageArtifactCounts,
  StageEvent,
  AIUsageDelta,
  PipelineRollup,
} from './pipeline-metrics.js';

export {
  getFindingMetrics,
  getFindingTimeSeries,
} from './finding-metrics.js';
export type {
  FindingAggregateStats,
  FindingTimeSeries,
  CountBy,
  DailyPoint,
} from './finding-metrics.js';

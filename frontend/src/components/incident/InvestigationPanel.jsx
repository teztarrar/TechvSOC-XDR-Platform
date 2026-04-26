import { memo, useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  X,
  Network,
  ShieldAlert,
  Users,
  Clock,
  AlertTriangle,
  Activity,
  Sparkles,
  BookOpen,
  Workflow,
} from "lucide-react";

import AttackGraphFlow from "./AttackGraphFlow";
import RiskScoreGauge from "./RiskScoreGauge";
import EntityList from "./EntityList";
import TimelineViewer from "./TimelineViewer";
import IncidentSummary from "./IncidentSummary";
import RecommendedActions from "./RecommendedActions";
import IncidentStoryPanel from "./IncidentStoryPanel";
import WorkflowPanel from "./WorkflowPanel";

const TAB_CONFIG = [
  { id: "story", label: "Story", icon: BookOpen },
  { id: "overview", label: "Overview", icon: Activity },
  { id: "intelligence", label: "Intelligence", icon: Sparkles },
  { id: "workflow", label: "Workflow", icon: Workflow },
  { id: "graph", label: "Attack Graph", icon: Network },
  { id: "entities", label: "Entities", icon: Users },
  { id: "timeline", label: "Timeline", icon: Clock },
  { id: "alerts", label: "Alerts", icon: ShieldAlert },
];

function computeRiskScore(incident) {
  const severityMap = { critical: 100, high: 75, medium: 50, low: 25 };
  const base = severityMap[incident.severity] || 50;

  const alertCount = incident.alerts?.length || 0;
  const alertBonus = Math.min(alertCount * 5, 20);

  const chainSteps = incident.attack_chain_json?.steps?.length || 0;
  const chainBonus = Math.min(chainSteps * 3, 15);

  const timelineEvents = incident.timeline_json?.length || 0;
  const timelineBonus = Math.min(timelineEvents * 2, 10);

  return Math.min(100, base + alertBonus + chainBonus + timelineBonus);
}

function SeverityBadge({ severity }) {
  const colors = {
    low: "border-emerald-400/30 text-emerald-300 bg-emerald-400/10",
    medium: "border-amber-400/30 text-amber-300 bg-amber-400/10",
    high: "border-rose-400/30 text-rose-300 bg-rose-400/10",
    critical: "border-fuchsia-400/30 text-fuchsia-300 bg-fuchsia-400/10",
  };
  return (
    <span
      className={`rounded-full border px-3 py-1 text-xs uppercase tracking-wider ${colors[severity] || colors.medium}`}
    >
      {severity}
    </span>
  );
}

function StatusBadge({ status }) {
  const colors = {
    new: "border-blue-400/30 text-blue-300 bg-blue-400/10",
    in_progress: "border-amber-400/30 text-amber-300 bg-amber-400/10",
    investigating: "border-yellow-400/30 text-yellow-300 bg-yellow-400/10",
    contained: "border-orange-400/30 text-orange-300 bg-orange-400/10",
    resolved: "border-emerald-400/30 text-emerald-300 bg-emerald-400/10",
    closed: "border-slate-400/30 text-slate-300 bg-slate-400/10",
  };
  return (
    <span
      className={`rounded-full border px-3 py-1 text-xs uppercase tracking-wider ${colors[status] || colors.new}`}
    >
      {status.replace("_", " ")}
    </span>
  );
}

function AlertCard({ alert, index }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.05 }}
      className="flex items-start justify-between gap-4 rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3 transition hover:border-white/20 hover:bg-white/[0.06]"
    >
      <div className="min-w-0">
        <p className="text-sm font-medium text-[var(--text-primary)]">{alert.title}</p>
        <p className="mt-0.5 text-xs text-[var(--text-muted)]">
          {alert.severity} -- {new Date(alert.triggered_at).toLocaleString()}
        </p>
      </div>
      <span className="shrink-0 rounded-full border border-white/10 bg-white/5 px-2 py-1 text-[10px] uppercase text-[var(--text-muted)]">
        {alert.status}
      </span>
    </motion.div>
  );
}

function InvestigationPanel({ incident, onClose, onIncidentUpdated }) {
  const [activeTab, setActiveTab] = useState("overview");

  const riskScore = useMemo(
    () => incident.risk_score ?? computeRiskScore(incident),
    [incident]
  );

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 flex justify-end bg-slate-950/70 p-2 backdrop-blur-sm sm:p-4"
        onClick={onClose}
      >
        <motion.div
          initial={{ x: "100%", opacity: 0.5 }}
          animate={{ x: 0, opacity: 1 }}
          exit={{ x: "100%", opacity: 0.5 }}
          transition={{ type: "spring", damping: 28, stiffness: 260 }}
          onClick={(e) => e.stopPropagation()}
          className="flex h-full w-full max-w-4xl flex-col overflow-hidden rounded-[2rem] border border-white/10 bg-[var(--surface-card)] shadow-glow"
        >
          {/* Header */}
          <div className="shrink-0 border-b border-white/10 px-6 py-5 sm:px-8">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <motion.h2
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="text-xl font-semibold text-[var(--text-primary)] sm:text-2xl"
                >
                  {incident.title}
                </motion.h2>
                <motion.p
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.1 }}
                  className="mt-1 line-clamp-2 text-sm text-[var(--text-muted)]"
                >
                  {incident.description}
                </motion.p>
              </div>
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={onClose}
                className="shrink-0 rounded-2xl border border-white/10 bg-white/5 px-4 py-2 text-sm text-[var(--text-primary)] transition hover:bg-white/10"
              >
                <X size={16} className="inline" />
              </motion.button>
            </div>

            <motion.div
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.15 }}
              className="mt-4 flex flex-wrap items-center gap-3"
            >
              <SeverityBadge severity={incident.severity} />
              <StatusBadge status={incident.status} />
              {incident.assigned_to_id && (
                <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs text-[var(--text-secondary)]">
                  Assigned: #{incident.assigned_to_id}
                </span>
              )}
              <span className="text-xs text-[var(--text-muted)]">
                {new Date(incident.created_at).toLocaleString()}
              </span>
            </motion.div>
          </div>

          {/* Tabs */}
          <div className="shrink-0 border-b border-white/10 px-4 sm:px-8">
            <div className="flex gap-1 overflow-x-auto py-3">
              {TAB_CONFIG.map((tab) => {
                const Icon = tab.icon;
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`relative flex shrink-0 items-center gap-2 rounded-xl px-4 py-2 text-xs font-medium uppercase tracking-wider transition-all ${
                      isActive
                        ? "text-brand-300"
                        : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
                    }`}
                  >
                    {isActive && (
                      <motion.div
                        layoutId="activeTab"
                        className="absolute inset-0 rounded-xl bg-brand-400/10"
                        transition={{ type: "spring", damping: 25, stiffness: 300 }}
                      />
                    )}
                    <Icon size={14} className="relative z-10" />
                    <span className="relative z-10">{tab.label}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Content */}
          <div className="flex-1 overflow-y-auto p-4 sm:p-8">
            <AnimatePresence mode="wait">
            {activeTab === "story" && (
                <motion.div
                  key="story"
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -12 }}
                  transition={{ duration: 0.25 }}
                >
                  <IncidentStoryPanel story={incident.story} />
                </motion.div>
              )}

              {activeTab === "overview" && (
                <motion.div
                  key="overview"
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -12 }}
                  transition={{ duration: 0.25 }}
                  className="space-y-6"
                >
                  <div className="grid gap-6 md:grid-cols-2">
                    <div className="flex flex-col items-center justify-center rounded-2xl border border-white/10 bg-white/[0.03] p-6">
                      <p className="mb-4 text-[10px] uppercase tracking-[0.2em] text-[var(--brand-muted)]">
                        Computed Risk Score
                      </p>
                      <RiskScoreGauge score={riskScore} size={160} />
                    </div>
                    <div className="space-y-4 rounded-2xl border border-white/10 bg-white/[0.03] p-6">
                      <p className="text-[10px] uppercase tracking-[0.2em] text-[var(--brand-muted)]">
                        Incident Summary
                      </p>
                      <div className="grid grid-cols-2 gap-4">
                        <div className="rounded-xl border border-white/10 bg-white/5 p-4 text-center">
                          <p className="text-2xl font-semibold text-[var(--text-primary)]">
                            {incident.alerts?.length || 0}
                          </p>
                          <p className="mt-1 text-xs text-[var(--text-muted)]">Related Alerts</p>
                        </div>
                        <div className="rounded-xl border border-white/10 bg-white/5 p-4 text-center">
                          <p className="text-2xl font-semibold text-[var(--text-primary)]">
                            {incident.attack_chain_json?.steps?.length || 0}
                          </p>
                          <p className="mt-1 text-xs text-[var(--text-muted)]">Attack Steps</p>
                        </div>
                        <div className="rounded-xl border border-white/10 bg-white/5 p-4 text-center">
                          <p className="text-2xl font-semibold text-[var(--text-primary)]">
                            {incident.timeline_json?.length || 0}
                          </p>
                          <p className="mt-1 text-xs text-[var(--text-muted)]">Timeline Events</p>
                        </div>
                        <div className="rounded-xl border border-white/10 bg-white/5 p-4 text-center">
                          <p className="text-2xl font-semibold text-[var(--text-primary)]">
                            {incident.status === "resolved" || incident.status === "closed"
                              ? incident.status.charAt(0).toUpperCase() + incident.status.slice(1)
                              : incident.status === "new"
                                ? "New"
                                : "Active"}
                          </p>
                          <p className="mt-1 text-xs text-[var(--text-muted)]">Status</p>
                        </div>
                      </div>
                    </div>
                  </div>

                  {incident.attack_chain_json && (
                    <div>
                      <p className="mb-3 flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-[var(--brand-muted)]">
                        <Network size={14} />
                        Attack Chain Preview
                      </p>
                      <AttackGraphFlow attackChain={incident.attack_chain_json} />
                    </div>
                  )}
                </motion.div>
              )}

              {activeTab === "intelligence" && (
                <motion.div
                  key="intelligence"
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -12 }}
                  transition={{ duration: 0.25 }}
                  className="space-y-6"
                >
                  <div className="grid gap-6 md:grid-cols-2">
                    <div className="flex flex-col items-center justify-center rounded-2xl border border-white/10 bg-white/[0.03] p-6">
                      <p className="mb-4 text-[10px] uppercase tracking-[0.2em] text-[var(--brand-muted)]">
                        Computed Risk Score
                      </p>
                      <RiskScoreGauge score={riskScore} size={160} />
                      <div className="mt-3 flex items-center gap-2">
                        <span
                          className={`rounded-full border px-2.5 py-0.5 text-[10px] uppercase tracking-wider ${
                            incident.confidence_level === "high"
                              ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-300"
                              : incident.confidence_level === "medium"
                              ? "border-amber-400/30 bg-amber-400/10 text-amber-300"
                              : "border-rose-400/30 bg-rose-400/10 text-rose-300"
                          }`}
                        >
                          {incident.confidence_level} confidence
                        </span>
                      </div>
                    </div>
                    <div className="space-y-4">
                      <IncidentSummary
                        summary={incident.ai_summary || "Analyzing incident data..."}
                        confidence={incident.confidence_level}
                      />
                    </div>
                  </div>

                  <div>
                    <p className="mb-3 flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-[var(--brand-muted)]">
                      <Sparkles size={14} />
                      Recommended Actions
                    </p>
                    <RecommendedActions actions={incident.recommended_actions || []} />
                  </div>
                </motion.div>
              )}

              {activeTab === "workflow" && (
                <motion.div
                  key="workflow"
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -12 }}
                  transition={{ duration: 0.25 }}
                >
                  <WorkflowPanel incident={incident} onIncidentUpdated={onIncidentUpdated} />
                </motion.div>
              )}

              {activeTab === "graph" && (
                <motion.div
                  key="graph"
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -12 }}
                  transition={{ duration: 0.25 }}
                  className="space-y-4"
                >
                  <div className="flex items-center justify-between">
                    <p className="flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-[var(--brand-muted)]">
                      <Network size={14} />
                      Attack Graph
                    </p>
                    <span className="text-xs text-[var(--text-muted)]">
                      {incident.attack_chain_json?.incident_type}
                    </span>
                  </div>
                  <AttackGraphFlow attackChain={incident.attack_chain_json} />
                </motion.div>
              )}

              {activeTab === "entities" && (
                <motion.div
                  key="entities"
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -12 }}
                  transition={{ duration: 0.25 }}
                >
                  <p className="mb-4 flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-[var(--brand-muted)]">
                    <Users size={14} />
                    Extracted Entities
                  </p>
                  <EntityList incident={incident} />
                </motion.div>
              )}

              {activeTab === "timeline" && (
                <motion.div
                  key="timeline"
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -12 }}
                  transition={{ duration: 0.25 }}
                >
                  <p className="mb-4 flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-[var(--brand-muted)]">
                    <Clock size={14} />
                    Event Timeline
                  </p>
                  <TimelineViewer events={incident.timeline_json || []} />
                </motion.div>
              )}

              {activeTab === "alerts" && (
                <motion.div
                  key="alerts"
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -12 }}
                  transition={{ duration: 0.25 }}
                  className="space-y-3"
                >
                  <p className="mb-2 flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-[var(--brand-muted)]">
                    <ShieldAlert size={14} />
                    Related Alerts ({incident.alerts?.length || 0})
                  </p>
                  {incident.alerts?.length > 0 ? (
                    incident.alerts.map((alert, idx) => (
                      <AlertCard key={alert.id} alert={alert} index={idx} />
                    ))
                  ) : (
                    <div className="flex items-center gap-2 py-8 text-xs text-[var(--text-muted)]">
                      <AlertTriangle size={14} />
                      <span>No related alerts.</span>
                    </div>
                  )}
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}

export default memo(InvestigationPanel);


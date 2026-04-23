import { usePolling } from '../hooks/usePolling'

const SEVERITY_COLORS = {
  CRITICAL: 'border-red-700 bg-red-900/20',
  WARNING:  'border-amber-700 bg-amber-900/20',
  INFO:     'border-emerald-700 bg-emerald-900/20',
}

const SEVERITY_BADGE = {
  CRITICAL: 'bg-red-900/60 text-red-400',
  WARNING:  'bg-amber-900/60 text-amber-400',
  INFO:     'bg-emerald-900/60 text-emerald-400',
}

export default function LiveFeed() {
  const { data: logs = [], loading } = usePolling('/api/live-logs?n=50', 3000)

  // Normalise: the endpoint returns an array directly
  const entries = Array.isArray(logs) ? logs : []

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <h1 className="text-xl font-semibold text-slate-100">Live Feed</h1>
        <span className="flex items-center gap-1.5 text-xs text-emerald-400 bg-emerald-900/30 border border-emerald-800 px-2 py-0.5 rounded-full">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          Auto-refresh 3s
        </span>
      </div>

      {loading && !entries.length ? (
        <div className="space-y-3 animate-pulse">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-16 bg-slate-800 rounded-xl" />
          ))}
        </div>
      ) : entries.length === 0 ? (
        <div className="flex items-center justify-center h-40 text-slate-500">
          No logs yet. Start monitoring to see live data.
        </div>
      ) : (
        <div className="space-y-2">
          {entries.map((entry) => {
            const isAlert = entry.is_alert === 1 || entry.is_alert === true
            const colorClass = isAlert
              ? (SEVERITY_COLORS[entry.severity] ?? 'border-slate-700 bg-slate-900')
              : 'border-slate-700/50 bg-slate-900/40'

            return (
              <div
                key={entry.id}
                className={`border rounded-xl px-4 py-3 flex flex-col sm:flex-row sm:items-center gap-2 ${colorClass}`}
              >
                {/* Severity or LOG badge */}
                {isAlert ? (
                  <span className={`text-xs font-semibold px-2 py-0.5 rounded-full shrink-0 ${SEVERITY_BADGE[entry.severity] ?? ''}`}>
                    {entry.severity}
                  </span>
                ) : (
                  <span className="text-xs font-semibold px-2 py-0.5 rounded-full shrink-0 bg-slate-800 text-slate-400">
                    LOG
                  </span>
                )}

                {/* Timestamp */}
                <span className="text-xs text-slate-500 font-mono shrink-0 w-40">
                  {entry.timestamp?.slice(0, 19)}
                </span>

                {/* Source */}
                <span className="text-xs font-medium text-cyan-400 shrink-0 w-28 truncate">
                  {entry.source ?? ''}
                </span>

                {/* Message or description */}
                <span className="text-xs text-slate-300 truncate flex-1">
                  {isAlert ? entry.description : entry.message}
                </span>

                {/* Event type for alerts */}
                {isAlert && entry.event_type && (
                  <span className="text-xs text-slate-500 shrink-0">
                    {entry.event_type.replace(/_/g, ' ')}
                  </span>
                )}

                {/* Source IP for alerts */}
                {isAlert && entry.source_ip && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-900/40 text-red-300 border border-red-800 font-mono shrink-0">
                    {entry.source_ip}
                  </span>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

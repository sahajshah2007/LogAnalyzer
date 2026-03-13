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
  const { data = [], loading } = usePolling('/api/alerts/recent?n=20', 3000)

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <h1 className="text-xl font-semibold text-slate-100">Live Feed</h1>
        <span className="flex items-center gap-1.5 text-xs text-emerald-400 bg-emerald-900/30 border border-emerald-800 px-2 py-0.5 rounded-full">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          Auto-refresh 3s
        </span>
      </div>

      {loading && !data?.length ? (
        <div className="space-y-3 animate-pulse">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-16 bg-slate-800 rounded-xl" />
          ))}
        </div>
      ) : data?.length === 0 ? (
        <div className="flex items-center justify-center h-40 text-slate-500">
          No alerts yet. Start monitoring to see live data.
        </div>
      ) : (
        <div className="space-y-2">
          {data.map((alert) => (
            <div
              key={alert.id}
              className={`border rounded-xl px-4 py-3 flex flex-col sm:flex-row sm:items-center gap-2 ${SEVERITY_COLORS[alert.severity] ?? 'border-slate-700 bg-slate-900'}`}
            >
              <span
                className={`text-xs font-semibold px-2 py-0.5 rounded-full shrink-0 ${SEVERITY_BADGE[alert.severity] ?? ''}`}
              >
                {alert.severity}
              </span>
              <span className="text-xs text-slate-500 font-mono shrink-0 w-40">{alert.timestamp?.slice(0,19)}</span>
              <span className="text-xs font-medium text-cyan-400 shrink-0 w-36 truncate">{alert.source_ip}</span>
              <span className="text-xs text-slate-300 truncate flex-1">{alert.description}</span>
              <span className="text-xs text-slate-500 shrink-0">{alert.event_type?.replace(/_/g,' ')}</span>
              {Array.isArray(alert.mitre_tactics) && alert.mitre_tactics.length > 0 && (
                <div className="flex flex-wrap gap-1 shrink-0">
                  {alert.mitre_tactics.map(t => (
                    <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-purple-900/50 text-purple-300 border border-purple-800">{t}</span>
                  ))}
                </div>
              )}
              {Array.isArray(alert.mitre_techniques) && alert.mitre_techniques.length > 0 && (
                <div className="flex flex-wrap gap-1 shrink-0">
                  {alert.mitre_techniques.map(t => (
                    <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-900/50 text-cyan-300 border border-cyan-800 font-mono">{t}</span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

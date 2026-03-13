import { AlertTriangle, ShieldOff, Activity, Clock } from 'lucide-react'

const CARDS = [
  {
    key: 'total_alerts',
    label: 'Total Alerts',
    icon: ShieldOff,
    color: 'text-cyan-400',
    bg: 'bg-cyan-900/20 border-cyan-800/40',
  },
  {
    key: 'alerts_last_hour',
    label: 'Last Hour',
    icon: Clock,
    color: 'text-violet-400',
    bg: 'bg-violet-900/20 border-violet-800/40',
  },
  {
    key: '_critical',
    label: 'Critical',
    icon: AlertTriangle,
    color: 'text-red-400',
    bg: 'bg-red-900/20 border-red-800/40',
  },
  {
    key: '_top_type',
    label: 'Top Attack',
    icon: Activity,
    color: 'text-amber-400',
    bg: 'bg-amber-900/20 border-amber-800/40',
  },
]

export default function StatsCards({ stats }) {
  const critical  = stats.by_severity?.find((s) => s.severity === 'CRITICAL')?.count ?? 0
  const topType   = stats.by_type?.[0]?.event_type?.replace(/_/g, ' ') ?? '—'

  const values = {
    total_alerts:      stats.total_alerts?.toLocaleString() ?? 0,
    alerts_last_hour:  stats.alerts_last_hour?.toLocaleString() ?? 0,
    _critical:         critical.toLocaleString(),
    _top_type:         topType,
  }

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      {CARDS.map(({ key, label, icon: Icon, color, bg }) => (
        <div
          key={key}
          className={`rounded-xl border p-5 flex flex-col gap-2 ${bg}`}
        >
          <div className="flex items-center justify-between">
            <span className="text-sm text-slate-400">{label}</span>
            <Icon size={18} className={color} />
          </div>
          <span className={`text-2xl font-bold ${color}`}>{values[key]}</span>
        </div>
      ))}
    </div>
  )
}

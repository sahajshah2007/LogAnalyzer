import { usePolling } from '../hooks/usePolling'
import StatsCards from './StatsCards'
import SeverityChart from './SeverityChart'
import AttackTypeChart from './AttackTypeChart'
import TimelineChart from './TimelineChart'
import TopIPs from './TopIPs'
import MonitorControl from './MonitorControl'

export default function Dashboard() {
  const { data: stats, loading, error } = usePolling('/api/stats', 8000)

  if (loading) return <Skeleton />
  if (error)   return <Error msg={error} />

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-slate-100">Overview</h1>
        <MonitorControl />
      </div>

      <StatsCards stats={stats} />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <TimelineChart />
        </div>
        <SeverityChart data={stats.by_severity} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <AttackTypeChart data={stats.by_type} />
        <TopIPs data={stats.top_ips} />
      </div>
    </div>
  )
}

function Skeleton() {
  return (
    <div className="space-y-6 animate-pulse">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="h-28 bg-slate-800 rounded-xl" />
        ))}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 h-64 bg-slate-800 rounded-xl" />
        <div className="h-64 bg-slate-800 rounded-xl" />
      </div>
    </div>
  )
}

function Error({ msg }) {
  return (
    <div className="flex flex-col items-center justify-center h-64 text-slate-400 gap-2">
      <span className="text-red-400 text-lg">⚠ API unreachable</span>
      <span className="text-sm">{msg}</span>
      <span className="text-xs">Make sure the API server is running on port 5005</span>
    </div>
  )
}

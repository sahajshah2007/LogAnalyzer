import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import { usePolling } from '../hooks/usePolling'

export default function TimelineChart() {
  const { data = [], loading } = usePolling('/api/attacks/timeline', 10000)

  const chartData = (data || []).map((d) => ({
    hour:  d.hour?.slice(11, 16) ?? '',   // show HH:MM
    count: d.count,
  }))

  return (
    <Card title="Alerts — Last 24 Hours">
      {loading ? (
        <div className="h-[220px] bg-slate-800 animate-pulse rounded-lg" />
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <AreaChart data={chartData} margin={{ top: 4, right: 10, left: -10, bottom: 0 }}>
            <defs>
              <linearGradient id="grad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor="#0ea5e9" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
            <XAxis dataKey="hour" tick={{ fill: '#94a3b8', fontSize: 11 }} />
            <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} />
            <Tooltip
              contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8 }}
              labelStyle={{ color: '#cbd5e1' }}
              itemStyle={{ color: '#38bdf8' }}
            />
            <Area
              type="monotone"
              dataKey="count"
              stroke="#0ea5e9"
              fill="url(#grad)"
              strokeWidth={2}
              dot={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </Card>
  )
}

function Card({ title, children }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <h2 className="text-sm font-semibold text-slate-400 mb-4">{title}</h2>
      {children}
    </div>
  )
}

import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts'

const COLORS = {
  CRITICAL: '#f87171',
  WARNING:  '#fbbf24',
  INFO:     '#34d399',
}

export default function SeverityChart({ data = [] }) {
  const chartData = data.map((d) => ({ name: d.severity, value: d.count }))

  return (
    <Card title="Alerts by Severity">
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Pie
            data={chartData}
            cx="50%"
            cy="50%"
            innerRadius={55}
            outerRadius={85}
            paddingAngle={3}
            dataKey="value"
          >
            {chartData.map((entry) => (
              <Cell key={entry.name} fill={COLORS[entry.name] ?? '#64748b'} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8 }}
            labelStyle={{ color: '#cbd5e1' }}
            itemStyle={{ color: '#e2e8f0' }}
          />
          <Legend
            formatter={(v) => <span className="text-slate-300 text-xs">{v}</span>}
          />
        </PieChart>
      </ResponsiveContainer>
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

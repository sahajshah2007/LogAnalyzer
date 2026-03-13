import { useState } from 'react'
import Navbar from './components/Navbar'
import Dashboard from './components/Dashboard'
import AlertsTable from './components/AlertsTable'
import LiveFeed from './components/LiveFeed'
import LogAnalyzer from './components/LogAnalyzer'

const TABS = ['Dashboard', 'Alerts', 'Live Feed', 'Log Analyzer']

export default function App() {
  const [tab, setTab] = useState('Dashboard')

  return (
    <div className="min-h-screen flex flex-col">
      <Navbar activeTab={tab} onTabChange={setTab} tabs={TABS} />
      <main className="flex-1 max-w-screen-2xl mx-auto w-full px-4 py-6">
        {tab === 'Dashboard'    && <Dashboard />}
        {tab === 'Alerts'       && <AlertsTable />}
        {tab === 'Live Feed'    && <LiveFeed />}
        {tab === 'Log Analyzer' && <LogAnalyzer />}
      </main>
    </div>
  )
}

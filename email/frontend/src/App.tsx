import React, { useEffect, useState } from 'react';
import { Shield, ShieldAlert, CheckCircle2, AlertTriangle, ChevronDown, ChevronUp, Server, Activity } from 'lucide-react';
import { cn } from './lib/utils';
import { PendingApprovals } from './components/PendingApprovals';
import { ActiveDatabase } from './components/ActiveDatabase';

// Types corresponding to the backend data
interface PipelineResult {
  scl_score: number;
  verdict: 'CLEAN' | 'SUSPICIOUS' | 'LIKELY_PHISH' | 'PHISH';
  l1_score: number;
  l2_heuristics_score: number;
  l2_nlp_score: number;
  l3_score: number;
  fired_rules: string[];
  nlp_label: string;
  nlp_confidence: number;
  flagged_urls: string[];
}

interface EmailContext {
  message_id: string;
  subject: string;
  sender: string;
  date: string;
}

interface ScannedEmail {
  id: string;
  timestamp: string;
  context: EmailContext;
  result: PipelineResult;
}

const VerdictBadge = ({ verdict }: { verdict: PipelineResult['verdict'] }) => {
  if (verdict === 'CLEAN') return <span className="bg-phish-clean/20 text-phish-clean px-3 py-1 rounded-full text-xs font-bold dot-matrix uppercase tracking-widest border border-phish-clean/30 shadow-[0_0_10px_rgba(16,185,129,0.2)]">CLEAN</span>;
  if (verdict === 'SUSPICIOUS') return <span className="bg-phish-suspicious/20 text-phish-suspicious px-3 py-1 rounded-full text-xs font-bold dot-matrix-yellow uppercase tracking-widest border border-phish-suspicious/30 shadow-[0_0_10px_rgba(234,179,8,0.2)]">SUSPICIOUS</span>;
  return <span className="bg-phish-phish/20 text-phish-phish px-3 py-1 rounded-full text-xs font-bold dot-matrix-red uppercase tracking-widest border border-phish-phish/30 shadow-[0_0_10px_rgba(239,68,68,0.2)]">PHISHING</span>;
};

const EmailCard = ({ email }: { email: ScannedEmail }) => {
  const [expanded, setExpanded] = useState(false);
  const { context, result } = email;

  return (
    <div className="bg-card text-card-foreground border border-border rounded-xl shadow-lg mb-4 overflow-hidden transition-all duration-300 hover:border-primary/50">
      <div 
        className="p-5 flex items-center justify-between cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-4">
          <div className="bg-muted p-3 rounded-full">
            {result.verdict === 'CLEAN' ? <CheckCircle2 className="text-phish-clean w-6 h-6" /> : 
             result.verdict === 'SUSPICIOUS' ? <AlertTriangle className="text-phish-suspicious w-6 h-6" /> : 
             <ShieldAlert className="text-phish-phish w-6 h-6" />}
          </div>
          <div>
            <h3 className="font-semibold text-lg truncate max-w-md">{context.subject || '(No Subject)'}</h3>
            <p className="text-muted-foreground text-sm flex items-center gap-2">
              <span className="font-mono text-xs">{context.sender}</span> • {new Date(email.timestamp).toLocaleTimeString()}
            </p>
          </div>
        </div>
        
        <div className="flex items-center gap-6">
          <div className="text-right">
            <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">SCL Score</p>
            <p className={cn(
              "font-dot text-2xl font-bold",
              result.scl_score < 4 ? "text-phish-clean dot-matrix" : 
              result.scl_score < 7 ? "text-phish-suspicious dot-matrix-yellow" : "text-phish-phish dot-matrix-red"
            )}>{result.scl_score}/10</p>
          </div>
          <VerdictBadge verdict={result.verdict} />
          {expanded ? <ChevronUp className="text-muted-foreground" /> : <ChevronDown className="text-muted-foreground" />}
        </div>
      </div>

      {expanded && (
        <div className="border-t border-border p-5 bg-secondary/30 grid grid-cols-1 md:grid-cols-3 gap-6 animate-in slide-in-from-top-2">
          {/* L1 Auth */}
          <div className="bg-background rounded-lg p-4 border border-border">
            <h4 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3 border-b border-border pb-2">L1 Authentication</h4>
            <div className="flex justify-between items-center mb-2">
              <span className="text-sm">Score Contribution</span>
              <span className="font-dot text-lg">+{result.l1_score}</span>
            </div>
            <ul className="text-xs text-muted-foreground space-y-1 mt-3 list-disc pl-4">
              {result.fired_rules.filter(r => r.startsWith('L1')).map((r, i) => <li key={i}>{r}</li>)}
              {result.fired_rules.filter(r => r.startsWith('L1')).length === 0 && <li>All checks passed</li>}
            </ul>
          </div>

          {/* L2 Heuristics & NLP */}
          <div className="bg-background rounded-lg p-4 border border-border">
            <h4 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3 border-b border-border pb-2">L2 Heuristics & NLP</h4>
            <div className="flex justify-between items-center mb-2">
              <span className="text-sm">Heuristics Score</span>
              <span className="font-dot text-lg">+{result.l2_heuristics_score}</span>
            </div>
            <div className="flex justify-between items-center mb-2">
              <span className="text-sm">NLP Classifier</span>
              <span className="font-dot text-lg">+{result.l2_nlp_score}</span>
            </div>
            <p className="text-xs mb-2 mt-3">NLP Confidence: <span className="font-mono">{(result.nlp_confidence * 100).toFixed(1)}% ({result.nlp_label})</span></p>
            <ul className="text-xs text-muted-foreground space-y-1 list-disc pl-4">
              {result.fired_rules.filter(r => r.startsWith('L2')).map((r, i) => <li key={i}>{r}</li>)}
            </ul>
          </div>

          {/* L3 Threat Intel */}
          <div className="bg-background rounded-lg p-4 border border-border">
            <h4 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3 border-b border-border pb-2">L3 Threat Intel (MCP)</h4>
            <div className="flex justify-between items-center mb-2">
              <span className="text-sm">Score Contribution</span>
              <span className="font-dot text-lg">+{result.l3_score}</span>
            </div>
            <ul className="text-xs text-muted-foreground space-y-1 mt-3 list-disc pl-4">
              {result.fired_rules.filter(r => r.startsWith('L3')).map((r, i) => <li key={i}>{r}</li>)}
              {result.flagged_urls.map((url, i) => <li key={`url-${i}`} className="text-phish-phish truncate">{url}</li>)}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}

function App() {
  const [emails, setEmails] = useState<ScannedEmail[]>([]);
  const [connected, setConnected] = useState(false);
  const [activeTab, setActiveTab] = useState<'feed' | 'pending' | 'database'>('feed');

  useEffect(() => {
    const sse = new EventSource('http://127.0.0.1:8080/api/stream');
    
    sse.onopen = () => setConnected(true);
    sse.onerror = () => setConnected(false);
    
    sse.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'ping') return;
      
      if (data.type === 'history') {
        setEmails(data.data.reverse());
      } else if (data.type === 'new_result') {
        setEmails(prev => [data.data, ...prev].slice(0, 50)); // Keep last 50
      }
    };

    return () => sse.close();
  }, []);

  return (
    <div className="min-h-screen p-8 max-w-7xl mx-auto">
      <header className="flex items-center justify-between mb-8 border-b border-border pb-6">
        <div className="flex items-center gap-4">
          <div className="bg-primary/10 p-3 rounded-lg border border-primary/20 shadow-[0_0_15px_rgba(255,255,255,0.1)]">
            <Shield className="w-8 h-8 text-primary" />
          </div>
          <div>
            <h1 className="text-3xl font-bold tracking-tight">PhishGuard</h1>
            <p className="text-muted-foreground font-dot tracking-widest uppercase text-sm mt-1">L1-L3 Analysis Pipeline</p>
          </div>
        </div>
        
        <div className="flex items-center gap-3 bg-secondary px-4 py-2 rounded-full border border-border">
          <div className="relative flex h-3 w-3">
            {connected && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-phish-clean opacity-75"></span>}
            <span className={cn("relative inline-flex rounded-full h-3 w-3", connected ? "bg-phish-clean" : "bg-phish-phish")}></span>
          </div>
          <span className="font-mono text-sm uppercase">{connected ? 'System Online' : 'Connecting...'}</span>
        </div>
      </header>

      {/* Navigation Tabs */}
      <div className="flex space-x-6 mb-8 border-b border-border/50">
        <button 
          onClick={() => setActiveTab('feed')} 
          className={cn("pb-4 px-2 font-medium border-b-2 transition-colors", activeTab === 'feed' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground')}
        >
          Live Feed
        </button>
        <button 
          onClick={() => setActiveTab('pending')} 
          className={cn("pb-4 px-2 font-medium border-b-2 transition-colors", activeTab === 'pending' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground')}
        >
          Pending Approvals
        </button>
        <button 
          onClick={() => setActiveTab('database')} 
          className={cn("pb-4 px-2 font-medium border-b-2 transition-colors", activeTab === 'database' ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground')}
        >
          Active Database
        </button>
      </div>

      <main>
        {activeTab === 'feed' && (
          <div className="animate-in fade-in duration-300">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
          <div className="bg-card p-6 rounded-xl border border-border shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-muted-foreground font-medium">Emails Scanned</h3>
              <Activity className="w-5 h-5 text-muted-foreground" />
            </div>
            <p className="text-4xl font-dot">{emails.length}</p>
          </div>
          <div className="bg-card p-6 rounded-xl border border-border shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-muted-foreground font-medium">Phishing Blocked</h3>
              <ShieldAlert className="w-5 h-5 text-phish-phish" />
            </div>
            <p className="text-4xl font-dot text-phish-phish dot-matrix-red">
              {emails.filter(e => e.result.verdict === 'PHISH' || e.result.verdict === 'LIKELY_PHISH').length}
            </p>
          </div>
          <div className="bg-card p-6 rounded-xl border border-border shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-muted-foreground font-medium">Active Workers</h3>
              <Server className="w-5 h-5 text-phish-clean" />
            </div>
            <p className="text-4xl font-dot text-phish-clean dot-matrix">3</p>
            <p className="text-xs text-muted-foreground mt-2 font-mono">L1 / L2 / L3 (VT-MCP)</p>
          </div>
        </div>

        <h2 className="text-xl font-semibold mb-6 flex items-center gap-2">
          <Activity className="w-5 h-5" /> Live Scan Feed
        </h2>
        
        {emails.length === 0 ? (
          <div className="text-center py-20 bg-card rounded-xl border border-border border-dashed">
            <Activity className="w-12 h-12 text-muted-foreground mx-auto mb-4 opacity-50" />
            <h3 className="text-lg font-medium">Waiting for incoming emails...</h3>
            <p className="text-muted-foreground font-mono mt-2 text-sm">Listening on Pub/Sub webhook</p>
          </div>
        ) : (
          <div className="space-y-4">
            {emails.map(email => (
              <EmailCard key={email.id} email={email} />
            ))}
          </div>
        )}
          </div>
        )}

        {activeTab === 'pending' && (
          <div className="animate-in fade-in duration-300">
            <PendingApprovals />
          </div>
        )}

        {activeTab === 'database' && (
          <div className="animate-in fade-in duration-300">
            <ActiveDatabase />
          </div>
        )}
      </main>
    </div>
  );
}

export default App;

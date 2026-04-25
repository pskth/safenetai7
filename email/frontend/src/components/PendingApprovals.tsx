import React, { useEffect, useState } from 'react';
import { Check, X, Clock } from 'lucide-react';
import { supabase } from '../lib/supabase';

interface PendingReport {
  id: number;
  url: string;
  domain: string;
  reported_at: string;
}

export const PendingApprovals = () => {
  const [reports, setReports] = useState<PendingReport[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchReports = async () => {
    setLoading(true);
    const { data, error } = await supabase
      .from('pending_reports')
      .select('*')
      .order('reported_at', { ascending: false });
    
    if (data) setReports(data);
    setLoading(false);
  };

  useEffect(() => {
    fetchReports();
    
    // Subscribe to realtime changes
    const channel = supabase
      .channel('pending_reports_changes')
      .on('postgres_changes', { event: '*', schema: 'public', table: 'pending_reports' }, () => {
        fetchReports();
      })
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, []);

  const approveReport = async (report: PendingReport) => {
    // Insert into active tables
    if (report.url) {
      await supabase.from('scam_urls').insert({ url: report.url });
    }
    if (report.domain) {
      await supabase.from('suspicious_domains').insert({ domain: report.domain });
    }
    
    // Remove from pending
    await supabase.from('pending_reports').delete().eq('id', report.id);
    fetchReports();
  };

  const rejectReport = async (id: number) => {
    await supabase.from('pending_reports').delete().eq('id', id);
    fetchReports();
  };

  if (loading && reports.length === 0) return <div className="text-muted-foreground p-8">Loading pending reports...</div>;

  if (reports.length === 0) return (
    <div className="text-center py-20 bg-card rounded-xl border border-border border-dashed">
      <Check className="w-12 h-12 text-phish-clean mx-auto mb-4 opacity-50" />
      <h3 className="text-lg font-medium">All caught up!</h3>
      <p className="text-muted-foreground font-mono mt-2 text-sm">No pending reports to review</p>
    </div>
  );

  return (
    <div className="space-y-4">
      {reports.map(report => (
        <div key={report.id} className="bg-card border border-border rounded-xl p-5 flex items-center justify-between shadow-sm">
          <div className="flex items-start gap-4">
            <div className="bg-phish-suspicious/10 p-3 rounded-full mt-1">
              <Clock className="w-5 h-5 text-phish-suspicious" />
            </div>
            <div>
              <div className="font-mono text-sm mb-2 break-all">
                <span className="text-muted-foreground uppercase text-xs tracking-wider mr-2">URL:</span>
                {report.url || 'None'}
              </div>
              <div className="font-mono text-sm mb-2">
                <span className="text-muted-foreground uppercase text-xs tracking-wider mr-2">Domain:</span>
                {report.domain || 'None'}
              </div>
              <div className="text-xs text-muted-foreground mt-2">
                Reported: {new Date(report.reported_at).toLocaleString()}
              </div>
            </div>
          </div>
          <div className="flex gap-2">
            <button 
              onClick={() => approveReport(report)}
              className="bg-phish-clean/10 hover:bg-phish-clean/20 text-phish-clean p-2 rounded-lg transition-colors"
              title="Approve & Add to Database"
            >
              <Check className="w-5 h-5" />
            </button>
            <button 
              onClick={() => rejectReport(report.id)}
              className="bg-muted hover:bg-muted/80 text-muted-foreground p-2 rounded-lg transition-colors"
              title="Reject & Discard"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>
      ))}
    </div>
  );
};

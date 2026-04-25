"use client";

import {
  AlertTriangle,
  BookOpen,
  Bot,
  FileText,
  Flame,
  Link2,
  Mail,
  Search,
  ShieldAlert,
  ShieldCheck,
  Star,
  Sparkles,
  Target,
  Trophy,
  Activity,
  PieChart as PieChartIcon,
} from "lucide-react";
import Image from "next/image";
import { type ReactNode, useMemo, useState, useEffect } from "react";
import {
  BarChart,
  Bar,
  CartesianGrid,
  LineChart,
  Line,
  AreaChart,
  Area,
  Legend,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";

import { StatusBadge } from "~/components/safenet/status-badge";
import { Button } from "~/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "~/components/ui/card";
import { Input } from "~/components/ui/input";
import { Select } from "~/components/ui/select";
import { Textarea } from "~/components/ui/textarea";
import { api } from "~/trpc/react";

async function fileToBase64(file: File): Promise<string> {
  return await new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result;
      if (typeof result === "string") {
        resolve(result);
        return;
      }
      reject(new Error("Could not convert file to base64 string."));
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

type DashboardClientProps = {
  userName: string;
  userEmail: string;
  isAdmin: boolean;
};

type Section = "detect" | "impact" | "reports" | "edu" | "admin";

function bytesToLabel(sizeBytes: number): string {
  if (sizeBytes < 1024) return `${sizeBytes} B`;
  if (sizeBytes < 1024 * 1024) return `${(sizeBytes / 1024).toFixed(1)} KB`;
  return `${(sizeBytes / (1024 * 1024)).toFixed(1)} MB`;
}

function fileToDataUrl(mimeType: string, base64Data: string): string {
  if (base64Data.startsWith("data:")) {
    return base64Data;
  }
  return `data:${mimeType};base64,${base64Data}`;
}

const CHART_COLORS = [
  "var(--chart-1)",
  "var(--chart-2)",
  "var(--chart-3)",
  "var(--chart-4)",
  "var(--chart-5)",
];

const QUIZ_QUESTIONS = [
  {
    prompt: "A message says your account will be locked in 10 minutes unless you click now. Best first action?",
    options: [
      "Click quickly and verify later",
      "Ignore forever",
      "Verify through official app/site before any action",
      "Reply with your OTP to confirm identity",
    ],
    correctIndex: 2,
  },
  {
    prompt: "Which signal is strongest for a phishing page?",
    options: [
      "A domain that looks similar but not exact",
      "A well-known logo",
      "A long privacy policy",
      "A dark mode interface",
    ],
    correctIndex: 0,
  },
  {
    prompt: "You receive an unknown attachment from an urgent sender. What should you do first?",
    options: [
      "Open it in full trust mode",
      "Upload to Document Scanner and verify sender",
      "Forward to all contacts",
      "Disable antivirus to inspect it",
    ],
    correctIndex: 1,
  },
] as const;

export function DashboardClient({ userName, userEmail, isAdmin }: DashboardClientProps) {
  const [isMounted, setIsMounted] = useState(false);
  useEffect(() => {
    setIsMounted(true);
  }, []);

  const [activeSection, setActiveSection] = useState<Section>("detect");

  const [linkUrl, setLinkUrl] = useState("");
  const [domainValue, setDomainValue] = useState("");
  const [emailText, setEmailText] = useState("");
  const [senderDomain, setSenderDomain] = useState("");
  const [documentFile, setDocumentFile] = useState<File | null>(null);

  const [reportTitle, setReportTitle] = useState("");
  const [reportType, setReportType] = useState<"link" | "email" | "document" | "other">("link");
  const [reportDescription, setReportDescription] = useState("");
  const [reportUrl, setReportUrl] = useState("");
  const [reportEmail, setReportEmail] = useState("");
  const [reporterInfo, setReporterInfo] = useState("");
  const [proofFile, setProofFile] = useState<File | null>(null);
  const [reportSearch, setReportSearch] = useState("");
  const [reportFeedFilter, setReportFeedFilter] = useState<"all" | "link" | "email" | "document" | "other">("all");
  const [reportSort, setReportSort] = useState<"newest" | "oldest" | "evidence">("newest");
  const [quizAnswers, setQuizAnswers] = useState<Record<number, number>>({});

  const [moderationReason, setModerationReason] = useState("Verified indicators and community evidence");
  const [chatInput, setChatInput] = useState("");
  const [chatLog, setChatLog] = useState<Array<{ role: "user" | "assistant"; text: string }>>([
    {
      role: "assistant",
      text: "Support copilot online. Ask me to draft scam safety guidance or user-facing replies.",
    },
  ]);

  const summary = api.report.dashboardSummary.useQuery();
  const reportFeed = api.report.reportFeed.useQuery();
  const history = api.scan.history.useQuery();

  const adminOverview = api.admin.overview.useQuery(undefined, { enabled: isAdmin });
  const adminReports = api.admin.reviewReports.useQuery({ limit: 60 }, { enabled: isAdmin });

  const linkScan = api.scan.scanLink.useMutation({
    onSuccess: async () => {
      await Promise.all([summary.refetch(), history.refetch()]);
    },
  });
  const domainScan = api.scan.checkDomainAge.useMutation({
    onSuccess: async () => {
      await Promise.all([summary.refetch(), history.refetch()]);
    },
  });
  const emailScan = api.scan.scanEmail.useMutation({
    onSuccess: async () => {
      await Promise.all([summary.refetch(), history.refetch()]);
    },
  });
  const docScan = api.scan.scanDocument.useMutation({
    onSuccess: async () => {
      await Promise.all([summary.refetch(), history.refetch()]);
    },
  });

  const reportSubmit = api.report.submit.useMutation({
    onSuccess: async () => {
      if (isAdmin) {
        await Promise.all([summary.refetch(), reportFeed.refetch(), adminReports.refetch()]);
      } else {
        await Promise.all([summary.refetch(), reportFeed.refetch()]);
      }
      setReportTitle("");
      setReportDescription("");
      setReportUrl("");
      setReportEmail("");
      setReporterInfo("");
      setProofFile(null);
    },
  });

  const adminUpdate = api.admin.updateReportStatus.useMutation({
    onSuccess: async () => {
      if (isAdmin) {
        await Promise.all([adminReports.refetch(), reportFeed.refetch(), adminOverview.refetch()]);
      } else {
        await reportFeed.refetch();
      }
    },
  });

  const supportReply = api.admin.supportReply.useMutation();

  const stats = useMemo(() => {
    const reportsByType = adminOverview.data?.reportsByType ?? [];
    
    // Prepare chart data
    const chartDataReports = reportsByType.map(item => ({
      name: item.type.toUpperCase(),
      value: item._count._all
    }));
    
    const riskData = [
      { name: 'Safe', value: adminOverview.data?.safeScans ?? 0 },
      { name: 'Suspicious', value: adminOverview.data?.suspiciousScans ?? 0 },
      { name: 'Dangerous', value: adminOverview.data?.dangerousScans ?? 0 },
    ].filter(d => d.value > 0);

    return {
      totalScans: summary.data?.totalScans ?? 0,
      dangerousScans: summary.data?.dangerousScans ?? 0,
      totalReports: summary.data?.totalReports ?? 0,
      reportsByType,
      chartDataReports,
      riskData,
      totalDetectedGlobal: adminOverview.data?.totalScans ?? 0,
      userReportsGlobal: adminOverview.data?.totalReports ?? 0,
    };
  }, [summary.data, adminOverview.data]);

  const filteredReports = useMemo(() => {
    const normalizedSearch = reportSearch.trim().toLowerCase();
    const source = [...(reportFeed.data ?? [])];
    const filtered = source.filter((item) => {
      const matchesType = reportFeedFilter === "all" || item.type === reportFeedFilter;
      const haystack = [item.title, item.description, item.url ?? "", item.email ?? "", item.reporterInfo ?? ""]
        .join(" ")
        .toLowerCase();
      const matchesSearch = normalizedSearch.length === 0 || haystack.includes(normalizedSearch);
      return matchesType && matchesSearch;
    });

    filtered.sort((a, b) => {
      if (reportSort === "oldest") {
        return new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
      }
      if (reportSort === "evidence") {
        return b.uploads.length - a.uploads.length;
      }
      return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
    });

    return filtered;
  }, [reportFeed.data, reportFeedFilter, reportSearch, reportSort]);

  const reportFeedStats = useMemo(() => {
    const feed = reportFeed.data ?? [];
    const withEvidence = feed.filter((item) => item.uploads.length > 0).length;
    const linkOrEmail = feed.filter((item) => item.type === "link" || item.type === "email").length;
    return {
      total: feed.length,
      withEvidence,
      linkOrEmail,
    };
  }, [reportFeed.data]);

  const reportTypeChartData = useMemo(() => {
    const buckets = filteredReports.reduce<Record<string, number>>((acc, item) => {
      const key = item.type.toUpperCase();
      acc[key] = (acc[key] ?? 0) + 1;
      return acc;
    }, {});
    return Object.entries(buckets).map(([name, value]) => ({ name, value }));
  }, [filteredReports]);

  const reportTrendData = useMemo(() => {
    const days = 7;
    const map = new Map<string, { day: string; reports: number; evidence: number }>();
    for (let i = days - 1; i >= 0; i -= 1) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      const key = date.toISOString().slice(0, 10);
      map.set(key, {
        day: isMounted ? date.toLocaleDateString(undefined, { weekday: "short" }) : "",
        reports: 0,
        evidence: 0,
      });
    }

    filteredReports.forEach((item) => {
      const key = new Date(item.createdAt).toISOString().slice(0, 10);
      const bucket = map.get(key);
      if (!bucket) return;
      bucket.reports += 1;
      if (item.uploads.length > 0) {
        bucket.evidence += 1;
      }
    });

    return [...map.values()];
  }, [filteredReports]);

  const learningStats = useMemo(() => {
    const scans = history.data ?? [];
    const reportCount = summary.data?.totalReports ?? 0;
    const dangerDetections = scans.filter((scan) => scan.status === "dangerous").length;
    const quizCorrect = QUIZ_QUESTIONS.reduce((acc, q, idx) => (quizAnswers[idx] === q.correctIndex ? acc + 1 : acc), 0);

    const xp = scans.length * 8 + reportCount * 18 + dangerDetections * 6 + quizCorrect * 30;
    const level = Math.max(1, Math.floor(xp / 120) + 1);
    const xpToNext = level * 120 - xp;
    const streakDays = Math.min(30, Math.max(1, Math.ceil(scans.length / 2)));

    return {
      xp,
      level,
      xpToNext,
      streakDays,
      quizCorrect,
      badges: [
        reportCount >= 1 ? "First Reporter" : null,
        scans.length >= 5 ? "Scanner Apprentice" : null,
        dangerDetections >= 3 ? "Threat Hunter" : null,
        quizCorrect >= 2 ? "Awareness Pro" : null,
      ].filter((badge): badge is string => badge !== null),
    };
  }, [history.data, summary.data?.totalReports, quizAnswers]);

  const navItems: Array<{ key: Section; label: string; icon: ReactNode }> = [
    { key: "detect", label: "Detection Lab", icon: <ShieldCheck className="size-4 mr-2" /> },
    { key: "impact", label: "Impact Board", icon: <PieChartIcon className="size-4 mr-2" /> },
    { key: "reports", label: "Community Reports", icon: <AlertTriangle className="size-4 mr-2" /> },
    { key: "edu", label: "Edu Hub", icon: <BookOpen className="size-4 mr-2" /> },
  ];

  if (isAdmin) {
    navItems.push({ key: "admin", label: "Admin Studio", icon: <Activity className="size-4 mr-2" /> });
  }

  return (
    <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 px-4 py-8 md:px-8">
      {/* Top Header Command Center */}
      <section className="glass-panel rounded-3xl p-5 md:p-6 flex flex-col md:flex-row items-center justify-between gap-4 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-1/2 h-full bg-gradient-to-l from-primary/10 to-transparent -z-10"></div>
        <div>
          <p className="text-xs uppercase tracking-[0.25em] text-primary mb-1">Command Center</p>
          <h2 className="font-heading text-2xl font-bold tracking-tight text-foreground">ThreatOps + TrustOps</h2>
        </div>
        <div className="flex flex-wrap gap-2 justify-center">
          {navItems.map((item) => (
            <Button
              key={item.key}
              variant={activeSection === item.key ? "default" : "outline"}
              className="rounded-full px-5"
              onClick={() => setActiveSection(item.key)}
            >
              {item.icon}
              {item.label}
            </Button>
          ))}
        </div>
      </section>

      {/* Stats row */}
      <section className="grid gap-4 md:grid-cols-4">
        <MetricCard title="Total Scans" value={stats.totalDetectedGlobal || stats.totalScans} color="text-foreground" />
        <MetricCard title="High Risk Flags" value={stats.dangerousScans} color="text-destructive" />
        <MetricCard title="Global Reports" value={stats.userReportsGlobal || stats.totalReports} color="text-foreground" />
        <MetricCard title="Your Reports" value={stats.totalReports} color="text-foreground" />
      </section>

      {activeSection === "detect" && (
        <section className="grid gap-6 xl:grid-cols-2">
          <ScanCard
            icon={<Link2 className="size-5 text-primary" />}
            title="Link Scanner"
            description="Risk score, keyword extraction, and clear status labeling"
          >
            <Input className="glass-input" value={linkUrl} onChange={(e) => setLinkUrl(e.target.value)} placeholder="https://suspicious.site/login" />
            <Button className="w-full bg-primary/90 text-primary-foreground hover:bg-primary shadow-[0_0_10px_rgba(0,240,255,0.2)]" onClick={() => linkScan.mutate({ url: linkUrl })} disabled={linkScan.isPending || !linkUrl}>
              {linkScan.isPending ? "Scanning..." : "Scan Link"}
            </Button>
            {linkScan.data && (
              <ResultPanel>
                <div className="mb-2 flex items-center justify-between">
                  <p className="font-medium text-foreground">Risk Score: <span className="text-primary">{linkScan.data.riskScore}</span></p>
                  <StatusBadge status={linkScan.data.status} />
                </div>
                <p className="text-sm text-muted-foreground">Keywords: {linkScan.data.keywords.join(", ") || "None"}</p>
              </ResultPanel>
            )}
          </ScanCard>

          <ScanCard
            icon={<ShieldCheck className="size-5 text-secondary" />}
            title="Domain Age Checker"
            description="Detect risky newly-created domains using IP2WHOIS"
          >
            <Input className="glass-input" value={domainValue} onChange={(e) => setDomainValue(e.target.value)} placeholder="domain.com" />
            <Button className="w-full bg-secondary/90 text-secondary-foreground hover:bg-secondary shadow-[0_0_10px_rgba(176,38,255,0.2)]" onClick={() => domainScan.mutate({ domain: domainValue })} disabled={domainScan.isPending || !domainValue}>
              {domainScan.isPending ? "Checking..." : "Check Domain"}
            </Button>
            {domainScan.data && (
              <ResultPanel>
                <div className="mb-2 flex items-center justify-between">
                  <p className="font-medium text-foreground">{domainScan.data.domain}</p>
                  <StatusBadge status={domainScan.data.status} />
                </div>
                <p className="text-sm text-muted-foreground">Created: {domainScan.data.createdAt ? (isMounted ? new Date(domainScan.data.createdAt).toLocaleDateString() : "") : "Unknown"}</p>
                <p className="text-sm text-muted-foreground">Age: {domainScan.data.ageYears ? `${domainScan.data.ageYears.toFixed(2)} years` : "Unknown"}</p>
              </ResultPanel>
            )}
          </ScanCard>

          <ScanCard
            icon={<Mail className="size-5 text-emerald" />}
            title="Email Scanner"
            description="Analyze suspicious text and explain risk patterns"
          >
            <Input className="glass-input" value={senderDomain} onChange={(e) => setSenderDomain(e.target.value)} placeholder="sender-domain.com (optional)" />
            <Textarea className="glass-input min-h-[100px]" value={emailText} onChange={(e) => setEmailText(e.target.value)} placeholder="Paste suspicious email content" />
            <Button className="w-full bg-emerald/90 text-primary-foreground hover:bg-emerald shadow-[0_0_10px_rgba(0,255,157,0.2)]" onClick={() => emailScan.mutate({ emailText, senderDomain })} disabled={emailScan.isPending || emailText.length < 10}>
              {emailScan.isPending ? "Analyzing..." : "Scan Email"}
            </Button>
            {emailScan.data && (
              <ResultPanel>
                <div className="mb-2 flex items-center justify-between">
                  <p className="font-medium text-foreground">Risk Score: <span className="text-emerald">{emailScan.data.riskScore}</span></p>
                  <StatusBadge status={emailScan.data.status} />
                </div>
                <p className="text-sm text-muted-foreground">{emailScan.data.explanation}</p>
              </ResultPanel>
            )}
          </ScanCard>

          <ScanCard
            icon={<FileText className="size-5 text-accent" />}
            title="Document Scanner"
            description="Upload evidence and detect phishing intent"
          >
            <Input className="glass-input file:text-primary file:bg-primary/10 file:border-0 file:rounded-md" type="file" accept=".pdf,.docx,.txt" onChange={(e) => setDocumentFile(e.target.files?.[0] ?? null)} />
            <Button
              className="w-full bg-accent/90 text-accent-foreground hover:bg-accent shadow-[0_0_10px_rgba(255,42,84,0.2)]"
              disabled={!documentFile || docScan.isPending}
              onClick={async () => {
                if (!documentFile) return;
                const base64Data = await fileToBase64(documentFile);
                docScan.mutate({
                  fileName: documentFile.name,
                  mimeType: documentFile.type || "application/octet-stream",
                  base64Data,
                });
              }}
            >
              {docScan.isPending ? "Processing..." : "Scan Document"}
            </Button>
            {docScan.data && (
              <ResultPanel>
                <div className="mb-2 flex items-center justify-between">
                  <p className="font-medium text-foreground">Risk Score: <span className="text-accent">{docScan.data.riskScore}</span></p>
                  <StatusBadge status={docScan.data.status} />
                </div>
                <p className="text-sm text-muted-foreground">{docScan.data.verdict}</p>
              </ResultPanel>
            )}
          </ScanCard>
        </section>
      )}

      {activeSection === "impact" && (
        <section className="grid gap-6 lg:grid-cols-2">
          {isAdmin && (
            <Card className="glass-panel">
              <CardHeader>
                <CardTitle className="flex items-center gap-2"><PieChartIcon className="size-5 text-primary" /> Reports by Type</CardTitle>
                <CardDescription>Visual distribution of scam reports</CardDescription>
              </CardHeader>
              <CardContent className="h-64">
                {stats.chartDataReports.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={stats.chartDataReports}>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.18)" />
                      <XAxis dataKey="name" stroke="rgba(226,232,240,0.65)" />
                      <YAxis stroke="rgba(226,232,240,0.65)" />
                      <Tooltip contentStyle={{ backgroundColor: "rgba(12,18,32,0.92)", border: "1px solid rgba(226,232,240,0.12)" }} />
                      <Bar dataKey="value" fill="var(--primary)" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-muted-foreground">No report data to chart.</div>
                )}
              </CardContent>
            </Card>
          )}

          {isAdmin && (
            <Card className="glass-panel">
              <CardHeader>
                <CardTitle className="flex items-center gap-2"><ShieldAlert className="size-5 text-secondary" /> Risk Distribution</CardTitle>
                <CardDescription>Global scans by risk verdict</CardDescription>
              </CardHeader>
              <CardContent className="h-64">
                {stats.riskData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={stats.riskData}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={80}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {stats.riskData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: "rgba(12,18,32,0.92)", border: "1px solid rgba(226,232,240,0.12)" }} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                   <div className="flex h-full items-center justify-center text-muted-foreground">No risk data to chart.</div>
                )}
              </CardContent>
            </Card>
          )}

          <Card className="glass-panel">
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Activity className="size-5 text-emerald" /> Your Latest Activity</CardTitle>
              <CardDescription>Personal timeline of security checks</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="max-h-96 space-y-3 overflow-y-auto pr-2 custom-scrollbar">
                {(history.data ?? []).map((scan) => (
                  <div
                    key={scan.id}
                    className="flex items-center justify-between rounded-xl border border-border bg-muted/40 p-3 hover:bg-muted/60 transition-colors"
                  >
                    <div>
                      <p className="text-sm font-semibold uppercase tracking-wider text-foreground">{scan.type}</p>
                      <p className="text-xs text-muted-foreground mt-0.5">{isMounted ? new Date(scan.createdAt).toLocaleString() : ""}</p>
                    </div>
                    <StatusBadge status={scan.status} />
                  </div>
                ))}
                {(history.data ?? []).length === 0 && (
                  <p className="text-center text-muted-foreground mt-4">No recent activity.</p>
                )}
              </div>
            </CardContent>
          </Card>
        </section>
      )}

      {activeSection === "reports" && (
        <section className="flex flex-col gap-8">
          <Card className="glass-panel h-fit">
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><AlertTriangle className="size-5 text-accent" /> Self-Reporting System</CardTitle>
              <CardDescription>
                Submit verified incidents. Reports appear immediately in the public feed.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Input className="glass-input" value={reportTitle} onChange={(e) => setReportTitle(e.target.value)} placeholder="Report Title" />
                <Select
                  value={reportType}
                  onChange={(e) => setReportType(e.target.value as "link" | "email" | "document" | "other")}
                >
                  <option value="link">Link</option>
                  <option value="email">Email</option>
                  <option value="document">Document</option>
                  <option value="other">Other</option>
                </Select>
                <Textarea className="glass-input min-h-[100px]" value={reportDescription} onChange={(e) => setReportDescription(e.target.value)} placeholder="Describe the scam pattern and evidence" />
                <div className="grid gap-3 md:grid-cols-2">
                  <Input className="glass-input" value={reportUrl} onChange={(e) => setReportUrl(e.target.value)} placeholder="URL (optional)" />
                  <Input className="glass-input" value={reportEmail} onChange={(e) => setReportEmail(e.target.value)} placeholder="Email (optional)" />
                </div>
                <Input className="glass-input" value={reporterInfo} onChange={(e) => setReporterInfo(e.target.value)} placeholder="Reporter info (optional)" />
                <Input className="glass-input file:text-primary file:bg-primary/10 file:border-0 file:rounded-md" type="file" onChange={(e) => setProofFile(e.target.files?.[0] ?? null)} />
              </div>
              <Button
                className="w-full bg-emerald/90 text-primary-foreground hover:bg-emerald shadow-[0_0_15px_rgba(0,255,157,0.2)]"
                disabled={reportSubmit.isPending || reportDescription.length < 10 || reportTitle.length < 3}
                onClick={async () => {
                  const proofData =
                    proofFile == null
                      ? undefined
                      : {
                          fileName: proofFile.name,
                          mimeType: proofFile.type || "application/octet-stream",
                          base64Data: await fileToBase64(proofFile),
                          sizeBytes: proofFile.size,
                        };

                  reportSubmit.mutate({
                    title: reportTitle,
                    type: reportType,
                    description: reportDescription,
                    url: reportUrl,
                    email: reportEmail,
                    reporterInfo,
                    proofFile: proofData,
                  });
                }}
              >
                {reportSubmit.isPending ? "Submitting..." : "Submit Report"}
              </Button>
              {reportSubmit.data && <p className="text-sm text-emerald mt-2">Report received. Status: {reportSubmit.data.status.toUpperCase()}.</p>}
            </CardContent>
          </Card>

          <Card className="glass-panel">
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Sparkles className="size-5 text-primary" /> Community Reports Feed</CardTitle>
              <CardDescription>Real-time community-impact timeline</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="mb-4 grid gap-3 md:grid-cols-3">
                <div className="rounded-xl border border-border bg-background/30 px-3 py-2">
                  <p className="text-[11px] uppercase tracking-wider text-muted-foreground">Total Reports</p>
                  <p className="text-xl font-semibold text-foreground">{reportFeedStats.total}</p>
                </div>
                <div className="rounded-xl border border-border bg-background/30 px-3 py-2">
                  <p className="text-[11px] uppercase tracking-wider text-muted-foreground">With Evidence</p>
                  <p className="text-xl font-semibold text-primary">{reportFeedStats.withEvidence}</p>
                </div>
                <div className="rounded-xl border border-border bg-background/30 px-3 py-2">
                  <p className="text-[11px] uppercase tracking-wider text-muted-foreground">Link/Email Reports</p>
                  <p className="text-xl font-semibold text-foreground">{reportFeedStats.linkOrEmail}</p>
                </div>
              </div>

              <div className="mb-4 grid gap-4 lg:grid-cols-2">
                <div className="rounded-xl border border-border bg-background/30 p-3">
                  <p className="mb-2 text-xs uppercase tracking-wider text-muted-foreground">Reports Trend (7 Days)</p>
                  <div className="h-48">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={reportTrendData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.18)" />
                        <XAxis dataKey="day" stroke="rgba(226,232,240,0.65)" />
                        <YAxis stroke="rgba(226,232,240,0.65)" />
                        <Tooltip contentStyle={{ backgroundColor: "rgba(12,18,32,0.92)", border: "1px solid rgba(226,232,240,0.12)" }} />
                        <Legend />
                        <Area type="monotone" dataKey="reports" stroke="var(--primary)" fill="var(--primary)" fillOpacity={0.22} />
                        <Area type="monotone" dataKey="evidence" stroke="var(--secondary)" fill="var(--secondary)" fillOpacity={0.2} />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>
                <div className="rounded-xl border border-border bg-background/30 p-3">
                  <p className="mb-2 text-xs uppercase tracking-wider text-muted-foreground">Report Types (Filtered)</p>
                  <div className="h-48">
                    {reportTypeChartData.length > 0 ? (
                      <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={reportTypeChartData}>
                          <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.18)" />
                          <XAxis dataKey="name" stroke="rgba(226,232,240,0.65)" />
                          <YAxis stroke="rgba(226,232,240,0.65)" />
                          <Tooltip contentStyle={{ backgroundColor: "rgba(12,18,32,0.92)", border: "1px solid rgba(226,232,240,0.12)" }} />
                          <Line type="monotone" dataKey="value" stroke="var(--accent)" strokeWidth={3} dot={{ r: 4 }} activeDot={{ r: 6 }} />
                        </LineChart>
                      </ResponsiveContainer>
                    ) : (
                      <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
                        No type data for current filters.
                      </div>
                    )}
                  </div>
                </div>
              </div>

              <div className="mb-4 grid gap-3 md:grid-cols-3">
                <div className="relative md:col-span-2">
                  <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    className="glass-input pl-9"
                    value={reportSearch}
                    onChange={(e) => setReportSearch(e.target.value)}
                    placeholder="Search title, description, URL, email..."
                  />
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <Select
                    value={reportFeedFilter}
                    onChange={(e) => setReportFeedFilter(e.target.value as "all" | "link" | "email" | "document" | "other")}
                  >
                    <option value="all">All</option>
                    <option value="link">Link</option>
                    <option value="email">Email</option>
                    <option value="document">Doc</option>
                    <option value="other">Other</option>
                  </Select>
                  <Select
                    value={reportSort}
                    onChange={(e) => setReportSort(e.target.value as "newest" | "oldest" | "evidence")}
                  >
                    <option value="newest">Newest</option>
                    <option value="oldest">Oldest</option>
                    <option value="evidence">Evidence</option>
                  </Select>
                </div>
              </div>

              <div className="space-y-4 max-h-[800px] overflow-y-auto pr-2 custom-scrollbar">
                {filteredReports.map((item) => (
                  <div key={item.id} className="rounded-xl border border-border bg-muted/40 p-4 relative overflow-hidden group">
                    <div className="absolute top-0 left-0 w-1 h-full bg-primary/50 group-hover:bg-primary transition-colors"></div>
                    <div className="mb-2 flex items-center justify-between">
                      <p className="font-bold text-lg text-foreground">{item.title}</p>
                      <div className="flex items-center gap-2">
                        {item.uploads.length > 0 && (
                          <span className="rounded-full border border-emerald/30 bg-emerald/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-emerald">
                            Evidence {item.uploads.length}
                          </span>
                        )}
                        <span className="rounded-full border border-primary/30 bg-primary/10 px-3 py-1 text-xs uppercase tracking-wider text-primary">{item.type}</span>
                      </div>
                    </div>
                    <p className="mb-3 text-xs text-muted-foreground">
                      {isMounted ? new Date(item.createdAt).toLocaleString() : ""} {item.user?.name ? `• by ${item.user.name}` : ""}
                    </p>
                    <p className="text-sm text-foreground/90 whitespace-pre-wrap leading-relaxed">{item.description}</p>
                    
                    <div className="mt-3 space-y-1">
                      {item.url && <p className="text-sm text-primary break-all"><span className="opacity-50">URL:</span> {item.url}</p>}
                      {item.email && <p className="text-sm text-foreground break-all"><span className="opacity-50">Email:</span> {item.email}</p>}
                      {item.reporterInfo && <p className="text-xs text-muted-foreground"><span className="opacity-50">Reporter:</span> {item.reporterInfo}</p>}
                    </div>

                    {item.uploads.length > 0 && (
                      <div className="mt-4 space-y-2 rounded-lg border border-border bg-background/25 p-3">
                        <p className="text-xs uppercase tracking-widest text-emerald font-semibold">Attached Evidence</p>
                        {item.uploads.map((upload: { id: string; fileName: string; mimeType: string; sizeBytes: number; base64Data?: string | null }) => {
                          const safeBase64 = typeof upload.base64Data === "string" ? upload.base64Data : "";
                          const src = fileToDataUrl(upload.mimeType, safeBase64);
                          const isImage = upload.mimeType.startsWith("image/");

                          return (
                            <div key={upload.id} className="rounded-md border border-border bg-background/35 p-2">
                              <p className="text-xs text-muted-foreground mb-2 font-mono">
                                {upload.fileName} • {bytesToLabel(upload.sizeBytes)}
                              </p>
                              {isImage ? (
                                <Image
                                  src={src}
                                  alt={upload.fileName}
                                  width={1200}
                                  height={800}
                                  unoptimized
                                  className="max-h-64 w-full rounded-md border border-border object-contain bg-background/35"
                                />
                              ) : (
                                <a
                                  className="inline-block rounded bg-primary/15 px-3 py-1 text-xs text-primary hover:bg-primary/25 transition-colors"
                                  href={src}
                                  download={upload.fileName}
                                >
                                  Download File
                                </a>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                ))}
                {filteredReports.length === 0 && (
                  <div className="rounded-xl border border-border bg-muted/40 p-8 text-center text-muted-foreground">
                    <p>No matching reports found. Try a different filter or search term.</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </section>
      )}

      {activeSection === "edu" && (
        <section className="grid gap-6 lg:grid-cols-3">
          <Card className="glass-panel lg:col-span-2">
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><BookOpen className="size-5 text-emerald" /> Education Hub</CardTitle>
              <CardDescription>Security awareness for modern threats</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="rounded-xl border border-accent/30 bg-accent/10 p-5 relative overflow-hidden group">
                <div className="absolute top-0 right-0 w-24 h-24 bg-accent/20 rounded-full blur-2xl -mr-10 -mt-10"></div>
                <h3 className="mb-2 font-bold text-foreground text-lg flex items-center gap-2"><AlertTriangle className="size-4 text-accent" /> Anatomy of a Scam</h3>
                <p className="text-sm text-foreground/80 leading-relaxed">
                  Attackers exploit urgency, fear, rewards, and fake authority. They mimic trusted brands, ask for OTPs,
                  and push users to click malicious links quickly before verification. Always verify the source domain carefully.
                </p>
              </div>
              <div className="rounded-xl border border-primary/30 bg-primary/10 p-5 relative overflow-hidden group">
                <div className="absolute top-0 right-0 w-24 h-24 bg-primary/20 rounded-full blur-2xl -mr-10 -mt-10"></div>
                <h3 className="mb-2 font-bold text-foreground text-lg flex items-center gap-2"><ShieldCheck className="size-4 text-primary" /> Defense Strategies</h3>
                <p className="text-sm text-foreground/80 leading-relaxed">
                  Verify domain age, inspect sender domain, never share OTP/PIN, avoid unknown attachments, and report
                  suspicious campaigns. Pause first, then verify through official channels. Use our Link Scanner before clicking.
                </p>
              </div>

              <div className="rounded-xl border border-secondary/30 bg-secondary/10 p-5">
                <h3 className="mb-4 flex items-center gap-2 text-lg font-bold text-foreground">
                  <Target className="size-4 text-foreground" /> Quick Security Challenge
                </h3>
                <div className="space-y-4">
                  {QUIZ_QUESTIONS.map((question, idx) => (
                    <div key={question.prompt} className="rounded-lg border border-border bg-background/30 p-3">
                      <p className="mb-2 text-sm font-semibold text-foreground">
                        Q{idx + 1}. {question.prompt}
                      </p>
                      <div className="grid gap-2">
                        {question.options.map((option, optionIndex) => {
                          const isSelected = quizAnswers[idx] === optionIndex;
                          return (
                            <Button
                              key={option}
                              type="button"
                              variant={isSelected ? "default" : "outline"}
                              className={`h-auto justify-start px-3 py-2 text-left text-sm transition ${
                                isSelected
                                  ? "text-primary-foreground"
                                  : "text-muted-foreground hover:text-foreground"
                              }`}
                              onClick={() => {
                                setQuizAnswers((prev) => ({
                                  ...prev,
                                  [idx]: optionIndex,
                                }));
                              }}
                            >
                              {option}
                            </Button>
                          );
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="glass-panel">
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Trophy className="size-5 text-primary" /> Learning Gamification</CardTitle>
              <CardDescription>Level up your security awareness as you use SafeNet</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="rounded-xl border border-primary/30 bg-primary/10 p-4">
                  <p className="text-xs uppercase tracking-wider text-primary">Current Level</p>
                  <p className="mt-1 text-3xl font-black text-foreground">Lvl {learningStats.level}</p>
                  <p className="mt-1 text-sm text-muted-foreground">{learningStats.xp} XP total</p>
                  <div className="mt-3 h-2 overflow-hidden rounded-full bg-background/40">
                    <div
                      className="h-full rounded-full bg-primary transition-all"
                      style={{ width: `${Math.min(100, ((learningStats.xp % 120) / 120) * 100)}%` }}
                    />
                  </div>
                  <p className="mt-2 text-xs text-muted-foreground">{learningStats.xpToNext} XP to next level</p>
                </div>

                <div className="grid grid-cols-3 gap-2">
                  <div className="rounded-lg border border-border bg-muted/40 p-2 text-center">
                    <Flame className="mx-auto mb-1 size-4 text-accent" />
                    <p className="text-xs text-muted-foreground">Streak</p>
                    <p className="font-semibold">{learningStats.streakDays}d</p>
                  </div>
                  <div className="rounded-lg border border-border bg-muted/40 p-2 text-center">
                    <Star className="mx-auto mb-1 size-4 text-foreground" />
                    <p className="text-xs text-muted-foreground">Quiz</p>
                    <p className="font-semibold">{learningStats.quizCorrect}/{QUIZ_QUESTIONS.length}</p>
                  </div>
                  <div className="rounded-lg border border-border bg-muted/40 p-2 text-center">
                    <AlertTriangle className="mx-auto mb-1 size-4 text-destructive" />
                    <p className="text-xs text-muted-foreground">Badges</p>
                    <p className="font-semibold">{learningStats.badges.length}</p>
                  </div>
                </div>

                <div className="rounded-lg border border-secondary/30 bg-secondary/10 p-3">
                  <p className="mb-2 text-xs uppercase tracking-wider text-foreground">Unlocked Badges</p>
                  {learningStats.badges.length > 0 ? (
                    <div className="flex flex-wrap gap-2">
                      {learningStats.badges.map((badge) => (
                        <span key={badge} className="rounded-full border border-secondary/30 bg-secondary/20 px-2.5 py-1 text-xs text-foreground">
                          {badge}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground">No badges yet. Submit reports and complete quiz answers.</p>
                  )}
                </div>

                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Operator Name</p>
                  <p className="font-bold text-lg text-foreground">{userName}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Clearance Email</p>
                  <p className="font-mono text-sm text-primary">{userEmail}</p>
                </div>
                <div className="mt-6 rounded-lg border border-secondary/30 bg-secondary/10 p-4">
                  <p className="text-xs text-foreground leading-relaxed">
                    <span className="font-bold">SYSTEM NOTE:</span> Your activity helps train the community defense network. Every report increases global resilience.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </section>
      )}

      {activeSection === "admin" && isAdmin && (
        <section className="grid gap-6 xl:grid-cols-3">
          <Card className="glass-panel xl:col-span-2">
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><ShieldAlert className="size-5 text-accent" /> Admin Moderation Queue</CardTitle>
              <CardDescription>Approve or reject reports with manual override reasoning</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Input className="glass-input border-accent/30 focus-visible:ring-accent/20" value={moderationReason} onChange={(e) => setModerationReason(e.target.value)} placeholder="Moderation reason for override" />
              <div className="space-y-3">
                {(adminReports.data ?? []).map((report) => (
                  <div key={report.id} className="rounded-xl border border-border bg-muted/40 p-4 hover:bg-muted/60 transition-all">
                    <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                      <p className="font-bold text-lg">{report.title}</p>
                      <span className={`rounded-full px-3 py-1 text-xs uppercase font-bold tracking-wider ${
                        report.status === "approved"
                          ? "bg-emerald/20 text-emerald border border-emerald/30"
                          : report.status === "rejected"
                            ? "bg-destructive/20 text-destructive border border-destructive/30"
                            : "bg-secondary/20 text-foreground border border-secondary/30"
                      }`}>
                        {report.status}
                      </span>
                    </div>
                    <p className="mb-2 text-xs text-muted-foreground font-mono">
                      {new Date(report.createdAt).toLocaleString()} {report.user?.name ? `• BY: ${report.user.name}` : ""}
                    </p>
                    <p className="mb-4 text-sm text-foreground/90 whitespace-pre-wrap">{report.description}</p>
                    
                    <div className="space-y-1 mb-4">
                      {report.url && <p className="text-sm text-primary break-all"><span className="opacity-50">URL:</span> {report.url}</p>}
                      {report.email && <p className="text-sm text-foreground break-all"><span className="opacity-50">EMAIL:</span> {report.email}</p>}
                    </div>

                    {report.uploads.length > 0 && (
                      <div className="mb-4 space-y-2 rounded-lg border border-border bg-background/25 p-3">
                        <p className="text-xs uppercase tracking-wide text-primary font-semibold">Evidence Attached</p>
                        {report.uploads.map((upload: { id: string; fileName: string; mimeType: string; sizeBytes: number; base64Data?: string | null }) => {
                          const safeBase64 = typeof upload.base64Data === "string" ? upload.base64Data : "";
                          const src = fileToDataUrl(upload.mimeType, safeBase64);
                          const isImage = upload.mimeType.startsWith("image/");

                          return (
                            <div key={upload.id} className="rounded-md border border-border bg-background/35 p-2">
                              <p className="text-xs text-muted-foreground mb-2">
                                {upload.fileName} • {bytesToLabel(upload.sizeBytes)}
                              </p>
                              {isImage ? (
                                <Image
                                  src={src}
                                  alt={upload.fileName}
                                  width={1200}
                                  height={800}
                                  unoptimized
                                  className="max-h-48 w-full rounded-md border border-border object-contain bg-background/35"
                                />
                              ) : (
                                <a
                                  className="text-xs text-primary underline"
                                  href={src}
                                  download={upload.fileName}
                                >
                                  Download File
                                </a>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                    <div className="flex gap-3 pt-2 border-t border-border/70">
                      <Button className="bg-emerald/20 hover:bg-emerald/30 text-emerald border border-emerald/30" disabled={adminUpdate.isPending} onClick={() => adminUpdate.mutate({ reportId: report.id, status: "approved", reason: moderationReason })}>Approve Report</Button>
                      <Button className="bg-destructive/20 hover:bg-destructive/30 text-destructive border border-destructive/30" disabled={adminUpdate.isPending} onClick={() => adminUpdate.mutate({ reportId: report.id, status: "rejected", reason: moderationReason })}>Reject Report</Button>
                    </div>
                  </div>
                ))}
                {(adminReports.data ?? []).length === 0 && (
                  <div className="p-4 text-center text-muted-foreground border border-border rounded-xl bg-muted/30">Queue is empty.</div>
                )}
              </div>
            </CardContent>
          </Card>

          <Card className="glass-panel h-fit">
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Bot className="size-5 text-foreground" /> AI Copilot</CardTitle>
              <CardDescription>Admin support assistant powered by Gemini</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="h-[400px] space-y-3 overflow-y-auto rounded-xl border border-border bg-muted/40 p-4 custom-scrollbar">
                {chatLog.map((entry, idx) => (
                  <div key={`${entry.role}-${idx}`} className={`rounded-xl p-3 text-sm border ${
                    entry.role === "assistant" 
                      ? "bg-secondary/10 border-secondary/20 text-foreground" 
                      : "bg-primary/10 border-primary/20 text-foreground ml-4"
                  }`}>
                    <p className={`mb-1 text-[10px] uppercase font-bold tracking-wider ${entry.role === "assistant" ? "text-foreground" : "text-primary"}`}>
                      {entry.role === "assistant" ? "System Copilot" : "Admin"}
                    </p>
                    <p className="leading-relaxed">{entry.text}</p>
                  </div>
                ))}
              </div>
              <div className="space-y-2">
                <Textarea className="glass-input resize-none" value={chatInput} onChange={(e) => setChatInput(e.target.value)} placeholder="Ask copilot to draft guidance..." rows={3} />
                <Button
                  className="w-full bg-secondary/90 text-secondary-foreground hover:bg-secondary shadow-[0_0_15px_rgba(176,38,255,0.2)]"
                  disabled={supportReply.isPending || chatInput.trim().length < 4}
                  onClick={async () => {
                    const text = chatInput.trim();
                    setChatInput("");
                    setChatLog((prev) => [...prev, { role: "user", text }]);
                    const res = await supportReply.mutateAsync({ userMessage: text });
                    const replyText = typeof res.reply === "string"
                      ? res.reply
                      : "Support is currently busy. Please retry in a moment.";
                    setChatLog((prev) => [...prev, { role: "assistant", text: replyText }]);
                  }}
                >
                  <Bot className="mr-2 size-4" /> {supportReply.isPending ? "Processing..." : "Query Copilot"}
                </Button>
              </div>
            </CardContent>
          </Card>
        </section>
      )}
    </div>
  );
}

function MetricCard({ title, value, color }: { title: string; value: number; color: string }) {
  return (
    <Card className="glass-panel overflow-hidden relative group">
      <div className="absolute -bottom-6 -right-6 w-24 h-24 bg-muted rounded-full blur-xl group-hover:bg-muted/80 transition-colors"></div>
      <CardHeader className="pb-2">
        <CardDescription className="uppercase tracking-wider text-xs font-semibold">{title}</CardDescription>
      </CardHeader>
      <CardContent>
        <p className={`text-4xl font-black tracking-tighter ${color} drop-shadow-sm`}>{value}</p>
      </CardContent>
    </Card>
  );
}

function ScanCard({
  icon,
  title,
  description,
  children,
}: {
  icon: ReactNode;
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <Card className="glass-panel border-t-2" style={{ borderTopColor: 'var(--border)' }}>
      <CardHeader>
        <CardTitle className="flex items-center gap-3 text-xl">{icon} {title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">{children}</CardContent>
    </Card>
  );
}

function ResultPanel({ children }: { children: ReactNode }) {
  return <div className="mt-4 rounded-xl border border-border bg-background/30 p-4 shadow-inner">{children}</div>;
}

import { useState } from 'react';
import axios from 'axios';
import { Shield, AlertTriangle, FileText, Activity, Terminal, CheckCircle2, Lock } from 'lucide-react';

// Helper function to format underscores and capitalize words normally
const formatText = (text) => {
  if (!text) return '';
  return text.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
};

export default function App() {
  const [requirement, setRequirement] = useState('');
 
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000').replace(/\/+$/, '');

  const handleAnalyze = async () => {
  if (!requirement.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await axios.post(
        `${apiBaseUrl}/analyze-requirement`,
        { requirement_text: requirement },
        {
          headers: {
            
            'Content-Type': 'application/json'
          }
        }
      );
      setResult(response.data);
    } catch (err) {
      console.error(err);
      if (err.response?.status === 401) {
        setError('Invalid API key. Check the APP_API_KEY configured on the backend.');
      } else if (err.response?.status === 422) {
        setError('The requirement is invalid. Enter between 5 and 4000 characters.');
      } else if (err.response?.status === 429) {
        setError('Too many requests. Please wait a moment and try again.');
      } else if (err.response?.status >= 500) {
        setError('The backend could not complete the analysis. Check the server logs.');
      } else {
        setError('Backend connection failed. Make sure the FastAPI server is running.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-black text-gray-100 p-6 md:p-10 font-sans selection:bg-emerald-500 selection:text-black">
      <div className="max-w-5xl mx-auto space-y-8">
        
        {/* Header Section */}
        <header className="flex flex-col sm:flex-row items-start sm:items-center justify-between border-b border-zinc-800 pb-6 gap-4">
          <div className="flex items-center gap-3.5">
            <div className="p-2.5 bg-emerald-500/10 border border-emerald-500/20 rounded-xl">
              <Shield className="w-7 h-7 text-emerald-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                SRS Security Analyzer
                <span className="text-xs font-mono font-normal px-2 py-0.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-full">v1.2</span>
              </h1>
              <p className="text-xs text-zinc-400 mt-0.5">Hybrid Rule Engine + RAG + AI Security Audit Pipeline</p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono text-zinc-400 bg-zinc-900/80 px-3 py-1.5 rounded-lg border border-zinc-800">
            API-powered analysis
          </div>
        </header>

        {/* Input Section */}
        <section className="bg-zinc-950 p-6 sm:p-8 rounded-2xl border border-zinc-800 shadow-xl space-y-4">
          <label className="block text-sm font-medium text-zinc-300">
            Enter Software Requirement Specification (SRS) Text:
          </label>
          <textarea
            value={requirement}
            onChange={(e) => setRequirement(e.target.value)}
            rows={4}
            maxLength={4000}
            placeholder="e.g., Users can reset their password by entering their email address."
            className="w-full bg-black text-zinc-200 border border-zinc-800 rounded-xl p-4 focus:outline-none focus:border-emerald-500 font-mono text-sm resize-none transition-colors"
          />
          <p className="text-xs text-zinc-500 text-right">{requirement.length}/4000 characters</p>
          
          <button
            onClick={handleAnalyze}
            disabled={loading || !requirement.trim()}
            className="w-full bg-emerald-500 hover:bg-emerald-400 disabled:bg-zinc-900 disabled:text-zinc-600 text-black font-semibold py-3.5 px-6 rounded-xl transition duration-200 flex items-center justify-center gap-2.5 cursor-pointer shadow-lg shadow-emerald-500/10"
          >
            {loading ? (
              <>
                <Activity className="w-5 h-5 animate-spin" />
                <span>Running Hybrid Security Analysis...</span>
              </>
            ) : (
              <>
                <Lock className="w-4 h-4" />
                <span>Analyze Requirement</span>
              </>
            )}
          </button>
        </section>

        {error && (
          <div className="p-4 bg-red-950/30 border border-red-900/50 rounded-xl text-red-400 text-sm flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 flex-shrink-0 text-red-500" />
            <span>{error}</span>
          </div>
        )}

        {/* Results Section */}
        {result && (
          <div className="space-y-6 animate-fade-in">
            
            {/* Risk Summary Bar */}
            <div className="bg-zinc-950 p-6 rounded-2xl border border-zinc-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 shadow-md">
              <div>
                <span className="text-xs uppercase tracking-wider text-zinc-500 font-mono">Overall Risk Assessment</span>
                <div className="flex items-baseline gap-2 mt-1">
                  <span className="text-3xl font-extrabold text-white tracking-tight">
                    {result.rule_engine_analysis?.risk_score ?? result.overall_risk_score ?? 'N/A'}
                  </span>
                  <span className="text-sm font-medium text-zinc-500">/ 10 Risk Score</span>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <div className="px-4 py-2 bg-zinc-900 border border-zinc-800 rounded-xl text-xs flex items-center gap-2">
                  <span className="text-zinc-400">Status:</span> 
                  <strong className="text-emerald-400 font-mono uppercase tracking-wide">{formatText(result.status)}</strong>
                </div>
              </div>
            </div>

            {/* Grid Layout for Detailed Analysis */}
            <div className="grid md:grid-cols-2 gap-6">
              
              {/* Rule Engine & OWASP Findings */}
              <div className="bg-zinc-950 p-6 rounded-2xl border border-zinc-800 space-y-6 shadow-md flex flex-col justify-between">
                <div className="space-y-6">
                  <h3 className="text-base font-semibold text-white flex items-center gap-2.5 border-b border-zinc-800/80 pb-3">
                    <Terminal className="w-5 h-5 text-amber-400" />
                    Rule Engine & Ambiguities
                  </h3>
                  
                  {/* Ambiguities */}
                  <div>
                    <h4 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-3 font-mono">Ambiguities Detected</h4>
                    {result.rule_engine_analysis?.ambiguities_found?.length > 0 ? (
                      <ul className="space-y-2.5">
                        {result.rule_engine_analysis.ambiguities_found.map((item, idx) => (
                          <li key={idx} className="bg-black/60 p-3.5 rounded-xl border border-zinc-900 text-xs flex justify-between items-center">
                            <span className="text-amber-300 font-mono font-medium">Term: "{item.term}"</span>
                            <span className="px-2.5 py-1 bg-amber-500/10 text-amber-400 border border-amber-500/20 rounded-md text-[11px]">
                              {formatText(item.category)}
                            </span>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-xs text-zinc-500 italic bg-black/40 p-3 rounded-xl border border-zinc-900">No ambiguities detected.</p>
                    )}
                  </div>

                  {/* Security Gaps & OWASP */}
                  <div>
                    <h4 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-3 font-mono">Security Gaps & OWASP</h4>
                    {result.rule_engine_analysis?.security_gaps_found?.length > 0 ? (
                      <ul className="space-y-2.5">
                        {result.rule_engine_analysis.security_gaps_found.map((gap, idx) => (
                          <li key={idx} className="bg-black/60 p-3.5 rounded-xl border border-zinc-900 text-xs space-y-1.5">
                            <div className="flex justify-between items-center font-mono text-red-400 font-medium">
                              <span>{formatText(gap.category)}</span>
                              <span className="uppercase text-[10px] px-2 py-0.5 bg-red-950/80 border border-red-800/60 rounded text-red-300">
                                {gap.severity}
                              </span>
                            </div>
                            <p className="text-zinc-400 text-[11px] leading-relaxed">{gap.owasp_mapping}</p>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-xs text-zinc-500 italic bg-black/40 p-3 rounded-xl border border-zinc-900">No rule-level security gaps detected.</p>
                    )}
                  </div>
                </div>
              </div>

              {/* AI Deep Analysis & Flaws */}
              <div className="bg-zinc-950 p-6 rounded-2xl border border-zinc-800 space-y-6 shadow-md flex flex-col justify-between">
                <div className="space-y-4">
                  <h3 className="text-base font-semibold text-white flex items-center gap-2.5 border-b border-zinc-800/80 pb-3">
                    <FileText className="w-5 h-5 text-emerald-400" />
                    AI Deep Analysis & Flaws
                  </h3>

                  {result.ai_deep_analysis?.flaws?.length > 0 ? (
                    <div className="space-y-3">
                      <h4 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-2 font-mono">Identified Vulnerabilities</h4>
                      {result.ai_deep_analysis.flaws.map((flaw, idx) => (
                        <div key={idx} className="bg-black/60 p-4 rounded-xl border border-zinc-900 text-xs space-y-2.5">
                          <p className="font-semibold text-white text-sm leading-snug">{flaw.issue}</p>
                          <div className="flex flex-wrap gap-3 text-zinc-400 text-[11px] font-mono">
                            <span>OWASP: <strong className="text-zinc-200">{flaw.owasp}</strong></span>
                            <span>Severity: <strong className="text-red-400 uppercase">{flaw.severity}</strong></span>
                          </div>
                          <p className="text-zinc-300 bg-zinc-950 p-2.5 rounded-lg text-[11px] border border-zinc-900/80 leading-relaxed">
                            <strong className="text-zinc-400 font-mono">Evidence:</strong> {flaw.evidence}
                          </p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-zinc-500 italic bg-black/40 p-3 rounded-xl border border-zinc-900">No AI flaws reported.</p>
                  )}
                </div>
              </div>

            </div>

            {/* Suggested Secure Requirement Rewrite Section (Full Width) */}
            {result.ai_deep_analysis?.secure_requirement && (
              <div className="bg-zinc-950 p-6 sm:p-8 rounded-2xl border border-emerald-500/30 shadow-xl space-y-3 relative overflow-hidden">
                <div className="absolute top-0 left-0 w-1 h-full bg-emerald-500"></div>
                <h3 className="text-base font-semibold text-emerald-400 flex items-center gap-2.5">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  Recommended Secure Requirement (AI Rewrite)
                </h3>
                <p className="text-zinc-200 bg-black/80 p-5 rounded-xl border border-zinc-900 leading-relaxed text-sm font-mono tracking-wide">
                  {result.ai_deep_analysis.secure_requirement}
                </p>
              </div>
            )}

          </div>
        )}

      </div>
    </div>
  );
}

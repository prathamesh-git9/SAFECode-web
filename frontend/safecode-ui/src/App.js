import React, { useState } from 'react';
import { Shield, Code, AlertTriangle, CheckCircle, XCircle, Loader2 } from 'lucide-react';
import CodeScanner from './components/CodeScanner';
import FindingsList from './components/FindingsList';
import HealthStatus from './components/HealthStatus';

function App() {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [summary, setSummary] = useState(null);

  const handleScanComplete = (results) => {
    setFindings(results.findings || []);
    setSummary(results.summary);
    setError(null);
  };

  const handleScanError = (errorMessage) => {
    setError(errorMessage);
    setFindings([]);
    setSummary(null);
  };

  const handleFixComplete = (fixData) => {
    // Update findings with the fixed code results
    if (fixData.findings) {
      setFindings(fixData.findings);
      const summary_data = create_summary_stats(fixData.findings);
      setSummary(summary_data);
    }
    setError(null);
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-blue-600" />
              <div>
                <h1 className="text-2xl font-bold text-gray-900">SAFECode-Web</h1>
                <p className="text-sm text-gray-500">Security Code Analysis Tool</p>
              </div>
            </div>
            <HealthStatus />
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Code Scanner */}
          <div className="space-y-6">
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                <Code className="h-5 w-5 mr-2" />
                Code Analysis
              </h2>
                             <CodeScanner 
                 onScanComplete={handleScanComplete}
                 onScanError={handleScanError}
                 setLoading={setLoading}
                 loading={loading}
                 onFixComplete={handleFixComplete}
               />
            </div>

            {/* Summary */}
            {summary && (
              <div className="bg-white rounded-lg shadow p-6">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Analysis Summary</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div className="text-center p-4 bg-red-50 rounded-lg">
                    <div className="text-2xl font-bold text-red-600">{summary.critical || 0}</div>
                    <div className="text-sm text-red-600">Critical</div>
                  </div>
                  <div className="text-center p-4 bg-orange-50 rounded-lg">
                    <div className="text-2xl font-bold text-orange-600">{summary.high || 0}</div>
                    <div className="text-sm text-orange-600">High</div>
                  </div>
                  <div className="text-center p-4 bg-yellow-50 rounded-lg">
                    <div className="text-2xl font-bold text-yellow-600">{summary.medium || 0}</div>
                    <div className="text-sm text-yellow-600">Medium</div>
                  </div>
                  <div className="text-center p-4 bg-green-50 rounded-lg">
                    <div className="text-2xl font-bold text-green-600">{summary.low || 0}</div>
                    <div className="text-sm text-green-600">Low</div>
                  </div>
                </div>
                {summary.suppression_rate > 0 && (
                  <div className="mt-4 p-3 bg-blue-50 rounded-lg">
                    <div className="text-sm text-blue-700">
                      Suppression Rate: {summary.suppression_rate.toFixed(1)}%
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Findings List */}
          <div className="space-y-6">
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                <AlertTriangle className="h-5 w-5 mr-2" />
                Security Findings
              </h2>
              
              {loading && (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
                  <span className="ml-2 text-gray-600">Analyzing code...</span>
                </div>
              )}

              {error && (
                <div className="flex items-center p-4 bg-red-50 rounded-lg">
                  <XCircle className="h-5 w-5 text-red-600 mr-2" />
                  <span className="text-red-700">{error}</span>
                </div>
              )}

              {!loading && !error && findings.length === 0 && (
                <div className="flex items-center justify-center py-8 text-gray-500">
                  <CheckCircle className="h-8 w-8 mr-2" />
                  <span>No security findings detected</span>
                </div>
              )}

              {!loading && !error && findings.length > 0 && (
                <FindingsList findings={findings} />
              )}
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="bg-white border-t mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <p className="text-center text-sm text-gray-500">
            SAFECode-Web - Powered by Semgrep and AI Analysis
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;

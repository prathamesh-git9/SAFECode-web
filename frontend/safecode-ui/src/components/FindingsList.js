import React, { useState } from 'react';
import { ChevronDown, ChevronRight, AlertTriangle, Info, XCircle, CheckCircle } from 'lucide-react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { tomorrow } from 'react-syntax-highlighter/dist/esm/styles/prism';

const FindingsList = ({ findings }) => {
  const [expandedFindings, setExpandedFindings] = useState(new Set());

  const toggleFinding = (findingId) => {
    const newExpanded = new Set(expandedFindings);
    if (newExpanded.has(findingId)) {
      newExpanded.delete(findingId);
    } else {
      newExpanded.add(findingId);
    }
    setExpandedFindings(newExpanded);
  };

  const getSeverityIcon = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return <XCircle className="h-5 w-5 text-red-600" />;
      case 'high':
        return <AlertTriangle className="h-5 w-5 text-orange-600" />;
      case 'medium':
        return <AlertTriangle className="h-5 w-5 text-yellow-600" />;
      case 'low':
        return <Info className="h-5 w-5 text-blue-600" />;
      default:
        return <Info className="h-5 w-5 text-gray-600" />;
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-red-50 border-red-200';
      case 'high':
        return 'bg-orange-50 border-orange-200';
      case 'medium':
        return 'bg-yellow-50 border-yellow-200';
      case 'low':
        return 'bg-blue-50 border-blue-200';
      default:
        return 'bg-gray-50 border-gray-200';
    }
  };

  const getStatusBadge = (status) => {
    if (status === 'SUPPRESSED') {
      return (
        <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
          <CheckCircle className="h-3 w-3 mr-1" />
          Suppressed
        </span>
      );
    }
    return (
      <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-red-100 text-red-800">
        <AlertTriangle className="h-3 w-3 mr-1" />
        Active
      </span>
    );
  };

  const getLanguage = (filename) => {
    const ext = filename.split('.').pop()?.toLowerCase();
    switch (ext) {
      case 'c':
        return 'c';
      case 'cpp':
      case 'cc':
      case 'cxx':
        return 'cpp';
      case 'java':
        return 'java';
      case 'py':
        return 'python';
      case 'js':
        return 'javascript';
      case 'ts':
        return 'typescript';
      case 'php':
        return 'php';
      case 'rb':
        return 'ruby';
      case 'go':
        return 'go';
      case 'rs':
        return 'rust';
      default:
        return 'text';
    }
  };

  return (
    <div className="space-y-3">
      {findings.map((finding) => (
        <div
          key={finding.id}
          className={`border rounded-lg p-4 ${getSeverityColor(finding.severity)}`}
        >
          {/* Finding Header */}
          <div className="flex items-start justify-between">
            <div className="flex items-start space-x-3 flex-1">
              {getSeverityIcon(finding.severity)}
              <div className="flex-1 min-w-0">
                <div className="flex items-center space-x-2 mb-1">
                  <h4 className="text-sm font-semibold text-gray-900 truncate">
                    {finding.title}
                  </h4>
                  {getStatusBadge(finding.status)}
                </div>
                <div className="flex items-center space-x-4 text-xs text-gray-600">
                  <span>CWE-{finding.cwe_id}</span>
                  <span className="capitalize">{finding.severity}</span>
                  <span>Line {finding.line}</span>
                  <span>{finding.file}</span>
                </div>
                {finding.suppression_reason && (
                  <div className="mt-2 text-xs text-gray-600 bg-gray-100 p-2 rounded">
                    <strong>Suppression Reason:</strong> {finding.suppression_reason}
                  </div>
                )}
              </div>
            </div>
            <button
              onClick={() => toggleFinding(finding.id)}
              className="ml-2 p-1 hover:bg-gray-200 rounded"
            >
              {expandedFindings.has(finding.id) ? (
                <ChevronDown className="h-4 w-4" />
              ) : (
                <ChevronRight className="h-4 w-4" />
              )}
            </button>
          </div>

          {/* Expanded Content */}
          {expandedFindings.has(finding.id) && (
            <div className="mt-4 pt-4 border-t border-gray-200">
              <div className="bg-gray-900 rounded-lg overflow-hidden">
                <div className="px-4 py-2 bg-gray-800 text-gray-300 text-sm font-mono">
                  {finding.file}:{finding.line}
                </div>
                <SyntaxHighlighter
                  language={getLanguage(finding.file)}
                  style={tomorrow}
                  customStyle={{
                    margin: 0,
                    borderRadius: 0,
                    fontSize: '0.875rem',
                    lineHeight: '1.5'
                  }}
                  showLineNumbers
                  startingLineNumber={Math.max(1, finding.line - 2)}
                >
                  {finding.snippet}
                </SyntaxHighlighter>
              </div>
              
              {finding.context && (
                <div className="mt-3 p-3 bg-gray-50 rounded-lg">
                  <h5 className="text-sm font-medium text-gray-900 mb-2">Additional Context</h5>
                  <pre className="text-xs text-gray-700 whitespace-pre-wrap">
                    {JSON.stringify(finding.context, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
};

export default FindingsList;

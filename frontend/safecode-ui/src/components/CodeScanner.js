import React, { useState } from 'react';
import { Play, FileText, Settings, Wrench } from 'lucide-react';
import axios from 'axios';

const CodeScanner = ({ onScanComplete, onScanError, setLoading, loading, onFixComplete }) => {
  const [code, setCode] = useState('');
  const [filename, setFilename] = useState('example.c');
  const [ruleset, setRuleset] = useState('p/security-audit');
  const [fixedCode, setFixedCode] = useState('');
  const [showFixedCode, setShowFixedCode] = useState(false);

  const handleScan = async () => {
    if (!code.trim()) {
      onScanError('Please enter some code to analyze');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post('/scan', {
        filename: filename,
        code: code,
        ruleset: ruleset
      });

      onScanComplete(response.data);
    } catch (error) {
      console.error('Scan error:', error);
      const errorMessage = error.response?.data?.detail || 
                          error.message || 
                          'Failed to analyze code. Please try again.';
      onScanError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const handleExampleCode = () => {
    const exampleCode = `#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    char *input = "This is a very long string that will overflow the buffer";
    strcpy(buffer, input);  // CWE-120: Buffer overflow
    printf("%s", buffer);
    return 0;
}`;
    setCode(exampleCode);
    setFilename('vulnerable.c');
  };

  const handleFixCode = async () => {
    if (!code.trim()) {
      onScanError('Please enter some code to fix');
      return;
    }

    setLoading(true);
    try {
      const response = await axios.post('/fix', {
        filename: filename,
        code: code
      });

      setFixedCode(response.data.fixed_code);
      setShowFixedCode(true);
      if (onFixComplete) {
        onFixComplete(response.data);
      }
    } catch (error) {
      console.error('Fix error:', error);
      const errorMessage = error.response?.data?.detail || 
                          error.message || 
                          'Failed to fix code. Please try again.';
      onScanError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Filename and Ruleset */}
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label htmlFor="filename" className="block text-sm font-medium text-gray-700 mb-1">
            Filename
          </label>
          <input
            type="text"
            id="filename"
            value={filename}
            onChange={(e) => setFilename(e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="example.c"
          />
        </div>
        <div>
          <label htmlFor="ruleset" className="block text-sm font-medium text-gray-700 mb-1">
            Ruleset
          </label>
          <select
            id="ruleset"
            value={ruleset}
            onChange={(e) => setRuleset(e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="p/security-audit">Security Audit</option>
            <option value="p/owasp-top-ten">OWASP Top Ten</option>
            <option value="p/cwe-top-25">CWE Top 25</option>
          </select>
        </div>
      </div>

      {/* Code Input */}
      <div>
        <div className="flex justify-between items-center mb-2">
          <label htmlFor="code" className="block text-sm font-medium text-gray-700">
            Source Code
          </label>
          <button
            onClick={handleExampleCode}
            className="flex items-center text-sm text-blue-600 hover:text-blue-800"
          >
            <FileText className="h-4 w-4 mr-1" />
            Load Example
          </button>
        </div>
        <textarea
          id="code"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          rows={12}
          className="w-full px-3 py-2 border border-gray-300 rounded-md font-mono text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          placeholder="Enter your source code here..."
        />
      </div>

      {/* Scan and Fix Buttons */}
      <div className="flex justify-between items-center">
        <div className="flex space-x-2">
          <button
            onClick={handleScan}
            disabled={loading || !code.trim()}
            className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                Analyzing...
              </>
            ) : (
              <>
                <Play className="h-4 w-4 mr-2" />
                Scan Code
              </>
            )}
          </button>
          
          <button
            onClick={handleFixCode}
            disabled={loading || !code.trim()}
            className="flex items-center px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                Fixing...
              </>
            ) : (
              <>
                <Wrench className="h-4 w-4 mr-2" />
                Fix Code
              </>
            )}
          </button>
        </div>
        
        <div className="flex items-center text-sm text-gray-500">
          <Settings className="h-4 w-4 mr-1" />
          Powered by Flawfinder + GPT
        </div>
      </div>

      {/* Fixed Code Display */}
      {showFixedCode && fixedCode && (
        <div className="mt-4 p-4 bg-green-50 border border-green-200 rounded-lg">
          <h4 className="text-sm font-semibold text-green-800 mb-2">Fixed Code:</h4>
          <textarea
            value={fixedCode}
            readOnly
            rows={12}
            className="w-full px-3 py-2 border border-green-300 rounded-md font-mono text-sm bg-white"
          />
          <div className="mt-2 flex space-x-2">
            <button
              onClick={() => setCode(fixedCode)}
              className="px-3 py-1 bg-green-600 text-white text-sm rounded hover:bg-green-700"
            >
              Use Fixed Code
            </button>
            <button
              onClick={() => setShowFixedCode(false)}
              className="px-3 py-1 bg-gray-600 text-white text-sm rounded hover:bg-gray-700"
            >
              Hide
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default CodeScanner;

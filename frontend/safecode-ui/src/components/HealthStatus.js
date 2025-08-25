import React, { useState, useEffect } from 'react';
import { Wifi, WifiOff, CheckCircle, XCircle } from 'lucide-react';
import axios from 'axios';

const HealthStatus = () => {
  const [status, setStatus] = useState('checking');
  const [semgrepVersion, setSemgrepVersion] = useState(null);

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const response = await axios.get('/health');
        setStatus(response.data.status);
        setSemgrepVersion(response.data.semgrep_version);
      } catch (error) {
        setStatus('error');
        setSemgrepVersion(null);
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 30000); // Check every 30 seconds

    return () => clearInterval(interval);
  }, []);

  const getStatusIcon = () => {
    switch (status) {
      case 'healthy':
        return <CheckCircle className="h-5 w-5 text-green-600" />;
      case 'degraded':
        return <Wifi className="h-5 w-5 text-yellow-600" />;
      case 'error':
        return <XCircle className="h-5 w-5 text-red-600" />;
      default:
        return <WifiOff className="h-5 w-5 text-gray-400 animate-pulse" />;
    }
  };

  const getStatusText = () => {
    switch (status) {
      case 'healthy':
        return 'Backend Online';
      case 'degraded':
        return 'Backend Degraded';
      case 'error':
        return 'Backend Offline';
      default:
        return 'Checking...';
    }
  };

  const getStatusColor = () => {
    switch (status) {
      case 'healthy':
        return 'text-green-600';
      case 'degraded':
        return 'text-yellow-600';
      case 'error':
        return 'text-red-600';
      default:
        return 'text-gray-500';
    }
  };

  return (
    <div className="flex items-center space-x-2">
      {getStatusIcon()}
      <div className="text-sm">
        <div className={`font-medium ${getStatusColor()}`}>
          {getStatusText()}
        </div>
        {semgrepVersion && (
          <div className="text-xs text-gray-500">
            Semgrep {semgrepVersion}
          </div>
        )}
      </div>
    </div>
  );
};

export default HealthStatus;

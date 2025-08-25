"""Telemetry and metrics module for SAFECode-Web backend."""

import time
import statistics
from typing import Dict, List, Optional, Any
from collections import defaultdict, deque
import threading
import logging

from .models import TelemetryData, Alert
from .config import get_config


class StreamingPercentile:
    """Simple streaming percentile estimator."""
    
    def __init__(self, window_size: int = 100):
        """
        Initialize percentile estimator.
        
        Args:
            window_size: Size of the sliding window
        """
        self.window_size = window_size
        self.values = deque(maxlen=window_size)
        self.lock = threading.Lock()
    
    def add_value(self, value: float):
        """Add a new value to the estimator."""
        with self.lock:
            self.values.append(value)
    
    def get_percentile(self, percentile: float) -> float:
        """
        Get percentile value.
        
        Args:
            percentile: Percentile (0.0 to 1.0)
            
        Returns:
            float: Percentile value
        """
        with self.lock:
            if not self.values:
                return 0.0
            
            sorted_values = sorted(self.values)
            index = int(percentile * (len(sorted_values) - 1))
            return sorted_values[index]


class TelemetryCollector:
    """Collect and track telemetry data."""
    
    def __init__(self):
        """Initialize telemetry collector."""
        self.scan_requests_total = 0
        self.suppressions_total = 0
        self.timeouts_total = 0
        self.truncations_total = 0
        self.findings_by_cwe = defaultdict(int)
        self.scan_durations = StreamingPercentile()
        self.lock = threading.Lock()
        
        # Alert thresholds
        self.critical_findings_threshold = 5
        self.timeout_rate_threshold = 0.1  # 10%
        self.suppression_drift_threshold = 0.15  # 15%
        self.truncation_rate_threshold = 0.05  # 5%
        
        # Baseline tracking
        self.baseline_suppression_rate = None
        self.baseline_findings_by_cwe = {}
        
        self.logger = logging.getLogger(__name__)
    
    def record_scan_request(self, duration: float, findings: List[Dict], 
                          suppressions: int, timeout: bool = False, 
                          truncated: bool = False):
        """
        Record a scan request and its metrics.
        
        Args:
            duration: Scan duration in seconds
            findings: List of findings
            suppressions: Number of suppressions applied
            timeout: Whether the scan timed out
            truncated: Whether results were truncated
        """
        with self.lock:
            self.scan_requests_total += 1
            self.scan_durations.add_value(duration)
            self.suppressions_total += suppressions
            
            if timeout:
                self.timeouts_total += 1
            
            if truncated:
                self.truncations_total += 1
            
            # Count findings by CWE
            for finding in findings:
                cwe = finding.get('cwe_id', 'CWE-000')
                self.findings_by_cwe[cwe] += 1
    
    def get_telemetry_data(self) -> TelemetryData:
        """
        Get current telemetry data.
        
        Returns:
            TelemetryData: Current telemetry data
        """
        with self.lock:
            return TelemetryData(
                scan_requests_total=self.scan_requests_total,
                scan_duration_p50=self.scan_durations.get_percentile(0.5),
                scan_duration_p90=self.scan_durations.get_percentile(0.9),
                findings_by_cwe=dict(self.findings_by_cwe),
                suppressions_total=self.suppressions_total,
                timeouts_total=self.timeouts_total,
                truncations_total=self.truncations_total
            )
    
    def update_baseline(self, suppression_rate: float, findings_by_cwe: Dict[str, int]):
        """
        Update baseline metrics.
        
        Args:
            suppression_rate: Baseline suppression rate
            findings_by_cwe: Baseline findings by CWE
        """
        with self.lock:
            self.baseline_suppression_rate = suppression_rate
            self.baseline_findings_by_cwe = findings_by_cwe.copy()
    
    def generate_alerts(self) -> List[Alert]:
        """
        Generate alerts based on current metrics.
        
        Returns:
            List[Alert]: List of active alerts
        """
        alerts = []
        current_time = time.time()
        
        with self.lock:
            # Check for critical findings
            critical_findings = self.findings_by_cwe.get('CWE-120', 0) + \
                               self.findings_by_cwe.get('CWE-121', 0) + \
                               self.findings_by_cwe.get('CWE-122', 0)
            
            if critical_findings >= self.critical_findings_threshold:
                alerts.append(Alert(
                    level="critical",
                    message=f"High number of critical buffer overflow findings: {critical_findings}",
                    timestamp=current_time,
                    details={"critical_findings": critical_findings}
                ))
            
            # Check timeout rate
            if self.scan_requests_total > 0:
                timeout_rate = self.timeouts_total / self.scan_requests_total
                if timeout_rate > self.timeout_rate_threshold:
                    alerts.append(Alert(
                        level="warning",
                        message=f"High timeout rate: {timeout_rate:.2%}",
                        timestamp=current_time,
                        details={"timeout_rate": timeout_rate}
                    ))
            
            # Check truncation rate
            if self.scan_requests_total > 0:
                truncation_rate = self.truncations_total / self.scan_requests_total
                if truncation_rate > self.truncation_rate_threshold:
                    alerts.append(Alert(
                        level="warning",
                        message=f"High truncation rate: {truncation_rate:.2%}",
                        timestamp=current_time,
                        details={"truncation_rate": truncation_rate}
                    ))
            
            # Check suppression drift
            if self.baseline_suppression_rate is not None and self.scan_requests_total > 0:
                current_suppression_rate = self.suppressions_total / self.scan_requests_total
                drift = abs(current_suppression_rate - self.baseline_suppression_rate)
                
                if drift > self.suppression_drift_threshold:
                    alerts.append(Alert(
                        level="warning",
                        message=f"Suppression rate drift detected: {drift:.2%}",
                        timestamp=current_time,
                        details={
                            "current_rate": current_suppression_rate,
                            "baseline_rate": self.baseline_suppression_rate,
                            "drift": drift
                        }
                    ))
            
            # Check for unusual CWE patterns
            for cwe, count in self.findings_by_cwe.items():
                baseline_count = self.baseline_findings_by_cwe.get(cwe, 0)
                if baseline_count > 0:
                    increase = (count - baseline_count) / baseline_count
                    if increase > 0.5:  # 50% increase
                        alerts.append(Alert(
                            level="warning",
                            message=f"Unusual increase in {cwe} findings: {increase:.1%}",
                            timestamp=current_time,
                            details={
                                "cwe": cwe,
                                "current_count": count,
                                "baseline_count": baseline_count,
                                "increase": increase
                            }
                        ))
        
        return alerts
    
    def reset_metrics(self):
        """Reset all metrics (useful for testing)."""
        with self.lock:
            self.scan_requests_total = 0
            self.suppressions_total = 0
            self.timeouts_total = 0
            self.truncations_total = 0
            self.findings_by_cwe.clear()
            self.scan_durations = StreamingPercentile()
            self.baseline_suppression_rate = None
            self.baseline_findings_by_cwe.clear()


# Global telemetry instance
_telemetry = None


def get_telemetry() -> TelemetryCollector:
    """Get the global telemetry instance."""
    global _telemetry
    
    if _telemetry is None:
        _telemetry = TelemetryCollector()
    
    return _telemetry


def get_telemetry_collector() -> TelemetryCollector:
    """Get the global telemetry instance (alias for compatibility)."""
    return get_telemetry()


def record_scan_metrics(duration: float, findings: List[Dict], suppressions: int,
                       timeout: bool = False, truncated: bool = False):
    """
    Record scan metrics.
    
    Args:
        duration: Scan duration in seconds
        findings: List of findings
        suppressions: Number of suppressions applied
        timeout: Whether the scan timed out
        truncated: Whether results were truncated
    """
    telemetry = get_telemetry()
    telemetry.record_scan_request(duration, findings, suppressions, timeout, truncated)


def get_current_telemetry() -> TelemetryData:
    """
    Get current telemetry data.
    
    Returns:
        TelemetryData: Current telemetry data
    """
    telemetry = get_telemetry()
    return telemetry.get_telemetry_data()


def generate_alerts() -> List[Alert]:
    """
    Generate alerts based on current metrics.
    
    Returns:
        List[Alert]: List of active alerts
    """
    telemetry = get_telemetry()
    return telemetry.generate_alerts()


def update_baseline_metrics(suppression_rate: float, findings_by_cwe: Dict[str, int]):
    """
    Update baseline metrics.
    
    Args:
        suppression_rate: Baseline suppression rate
        findings_by_cwe: Baseline findings by CWE
    """
    telemetry = get_telemetry()
    telemetry.update_baseline(suppression_rate, findings_by_cwe)

"""Baseline management module for SAFECode-Web backend."""

import json
import os
from typing import Dict, List, Optional, Any
from pathlib import Path
import logging

from .models import BaselineReport
from .utils import as_utf8, create_summary_stats


class BaselineManager:
    """Manager for baseline scan results."""
    
    def __init__(self, baseline_dir: str = "baselines"):
        """
        Initialize baseline manager.
        
        Args:
            baseline_dir: Directory to store baseline files
        """
        self.baseline_dir = Path(baseline_dir)
        self.baseline_dir.mkdir(exist_ok=True)
        self.logger = logging.getLogger(__name__)
    
    def get_baseline_path(self, repo: str, branch: str) -> Path:
        """
        Get path for baseline file.
        
        Args:
            repo: Repository name
            branch: Branch name
            
        Returns:
            Path: Path to baseline file
        """
        # Sanitize repo and branch names for filesystem
        safe_repo = self._sanitize_name(repo)
        safe_branch = self._sanitize_name(branch)
        
        repo_dir = self.baseline_dir / safe_repo
        repo_dir.mkdir(exist_ok=True)
        
        return repo_dir / f"{safe_branch}.json"
    
    def _sanitize_name(self, name: str) -> str:
        """Sanitize name for filesystem use."""
        import re
        # Replace unsafe characters with underscores
        sanitized = re.sub(r'[^a-zA-Z0-9._-]', '_', name)
        # Limit length
        return sanitized[:50]
    
    def save_baseline(self, repo: str, branch: str, findings: List[Dict]) -> bool:
        """
        Save baseline scan results.
        
        Args:
            repo: Repository name
            branch: Branch name
            findings: List of findings
            
        Returns:
            bool: True if saved successfully
        """
        try:
            baseline_path = self.get_baseline_path(repo, branch)
            
            # Create summary statistics
            summary = create_summary_stats(findings)
            
            # Prepare baseline data
            baseline_data = {
                'repo': repo,
                'branch': branch,
                'timestamp': self._get_current_timestamp(),
                'findings_count': len(findings),
                'summary': summary,
                'findings': findings
            }
            
            # Write to file
            with open(baseline_path, 'w', encoding='utf-8') as f:
                json.dump(baseline_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Baseline saved: {baseline_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving baseline: {e}")
            return False
    
    def load_baseline(self, repo: str, branch: str) -> Optional[Dict]:
        """
        Load baseline scan results.
        
        Args:
            repo: Repository name
            branch: Branch name
            
        Returns:
            Optional[Dict]: Baseline data or None
        """
        try:
            baseline_path = self.get_baseline_path(repo, branch)
            
            if not baseline_path.exists():
                return None
            
            with open(baseline_path, 'r', encoding='utf-8') as f:
                baseline_data = json.load(f)
            
            self.logger.info(f"Baseline loaded: {baseline_path}")
            return baseline_data
            
        except Exception as e:
            self.logger.error(f"Error loading baseline: {e}")
            return None
    
    def compare_with_baseline(self, repo: str, branch: str, current_findings: List[Dict]) -> Optional[BaselineReport]:
        """
        Compare current findings with baseline.
        
        Args:
            repo: Repository name
            branch: Branch name
            current_findings: Current scan findings
            
        Returns:
            Optional[BaselineReport]: Comparison report or None
        """
        baseline_data = self.load_baseline(repo, branch)
        if not baseline_data:
            return None
        
        try:
            baseline_findings = baseline_data.get('findings', [])
            baseline_summary = baseline_data.get('summary', {})
            
            # Create current summary
            current_summary = create_summary_stats(current_findings)
            
            # Calculate drift
            baseline_suppression_rate = baseline_summary.get('suppression_rate', 0.0)
            current_suppression_rate = current_summary.get('suppression_rate', 0.0)
            drift = abs(current_suppression_rate - baseline_suppression_rate)
            
            # Count findings by severity and status
            active_by_severity = {}
            suppressed_by_severity = {}
            
            for finding in current_findings:
                severity = finding.get('severity', 'MEDIUM')
                status = finding.get('status', 'ACTIVE')
                
                if status == 'ACTIVE':
                    active_by_severity[severity] = active_by_severity.get(severity, 0) + 1
                else:
                    suppressed_by_severity[severity] = suppressed_by_severity.get(severity, 0) + 1
            
            # Calculate severity changes
            severity_changes = {}
            baseline_by_severity = baseline_summary.get('totals_by_severity', {})
            
            for severity in set(list(active_by_severity.keys()) + list(baseline_by_severity.keys())):
                current_count = active_by_severity.get(severity, 0)
                baseline_count = baseline_by_severity.get(severity, 0)
                
                if baseline_count > 0:
                    change = current_count - baseline_count
                    severity_changes[severity] = {
                        'current': current_count,
                        'baseline': baseline_count,
                        'change': change,
                        'change_percent': (change / baseline_count) * 100
                    }
            
            return BaselineReport(
                active=active_by_severity,
                suppressed=suppressed_by_severity,
                drift=drift if drift > 0.01 else None,  # Only show if significant
                severity_changes=severity_changes if severity_changes else None
            )
            
        except Exception as e:
            self.logger.error(f"Error comparing with baseline: {e}")
            return None
    
    def list_baselines(self) -> List[Dict]:
        """
        List all available baselines.
        
        Returns:
            List[Dict]: List of baseline information
        """
        baselines = []
        
        try:
            for repo_dir in self.baseline_dir.iterdir():
                if repo_dir.is_dir():
                    repo_name = repo_dir.name
                    
                    for baseline_file in repo_dir.glob("*.json"):
                        try:
                            with open(baseline_file, 'r', encoding='utf-8') as f:
                                data = json.load(f)
                            
                            baselines.append({
                                'repo': data.get('repo', repo_name),
                                'branch': data.get('branch', baseline_file.stem),
                                'timestamp': data.get('timestamp'),
                                'findings_count': data.get('findings_count', 0)
                            })
                        except Exception as e:
                            self.logger.warning(f"Error reading baseline {baseline_file}: {e}")
            
        except Exception as e:
            self.logger.error(f"Error listing baselines: {e}")
        
        return baselines
    
    def delete_baseline(self, repo: str, branch: str) -> bool:
        """
        Delete a baseline.
        
        Args:
            repo: Repository name
            branch: Branch name
            
        Returns:
            bool: True if deleted successfully
        """
        try:
            baseline_path = self.get_baseline_path(repo, branch)
            
            if baseline_path.exists():
                baseline_path.unlink()
                self.logger.info(f"Baseline deleted: {baseline_path}")
                return True
            else:
                self.logger.warning(f"Baseline not found: {baseline_path}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error deleting baseline: {e}")
            return False
    
    def _get_current_timestamp(self) -> str:
        """Get current timestamp string."""
        import datetime
        return datetime.datetime.now().isoformat()
    
    def get_baseline_stats(self, repo: str, branch: str) -> Optional[Dict]:
        """
        Get baseline statistics.
        
        Args:
            repo: Repository name
            branch: Branch name
            
        Returns:
            Optional[Dict]: Baseline statistics
        """
        baseline_data = self.load_baseline(repo, branch)
        if not baseline_data:
            return None
        
        return {
            'repo': baseline_data.get('repo'),
            'branch': baseline_data.get('branch'),
            'timestamp': baseline_data.get('timestamp'),
            'findings_count': baseline_data.get('findings_count', 0),
            'summary': baseline_data.get('summary', {})
        }


# Global baseline manager instance
_baseline_manager = None


def get_baseline_manager() -> BaselineManager:
    """Get the global baseline manager instance."""
    global _baseline_manager
    
    if _baseline_manager is None:
        _baseline_manager = BaselineManager()
    
    return _baseline_manager


def save_baseline(repo: str, branch: str, findings: List[Dict]) -> bool:
    """
    Save baseline scan results.
    
    Args:
        repo: Repository name
        branch: Branch name
        findings: List of findings
        
    Returns:
        bool: True if saved successfully
    """
    manager = get_baseline_manager()
    return manager.save_baseline(repo, branch, findings)


def load_baseline(repo: str, branch: str) -> Optional[Dict]:
    """
    Load baseline scan results.
    
    Args:
        repo: Repository name
        branch: Branch name
        
    Returns:
        Optional[Dict]: Baseline data or None
    """
    manager = get_baseline_manager()
    return manager.load_baseline(repo, branch)


def compare_with_baseline(repo: str, branch: str, current_findings: List[Dict]) -> Optional[BaselineReport]:
    """
    Compare current findings with baseline.
    
    Args:
        repo: Repository name
        branch: Branch name
        current_findings: Current scan findings
        
    Returns:
        Optional[BaselineReport]: Comparison report or None
    """
    manager = get_baseline_manager()
    return manager.compare_with_baseline(repo, branch, current_findings)


def list_baselines() -> List[Dict]:
    """
    List all available baselines.
    
    Returns:
        List[Dict]: List of baseline information
    """
    manager = get_baseline_manager()
    return manager.list_baselines()

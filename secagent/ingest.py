"""
Repository ingestion and environment loading.
"""

import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import git
from dotenv import load_dotenv
from rich.console import Console

console = Console()

class RepoIngestor:
    """Handles repository ingestion from local paths or Git URLs."""
    
    def __init__(self, run_dir: Path, verbose: bool = False):
        self.run_dir = run_dir
        self.verbose = verbose
        self.temp_dirs = []
    
    def ingest(self, repo: str, env_file: Optional[str] = None) -> Path:
        """
        Ingest repository from local path or Git URL.
        
        Args:
            repo: Local path or Git URL
            env_file: Optional .env file path
            
        Returns:
            Path to the repository directory
        """
        # Load environment file if provided
        if env_file:
            env_path = Path(env_file)
            if env_path.exists():
                load_dotenv(env_path)
                if self.verbose:
                    console.print(f"   Loaded environment from {env_path}")
            else:
                console.print(f"   ⚠️  Environment file not found: {env_path}", style="yellow")
        
        # Determine if repo is a URL or local path
        parsed = urlparse(repo)
        if parsed.scheme in ('http', 'https', 'git', 'ssh'):
            return self._clone_repo(repo)
        else:
            return self._use_local_repo(repo)
    
    def _clone_repo(self, git_url: str) -> Path:
        """Clone repository from Git URL."""
        if self.verbose:
            console.print(f"   Cloning repository: {git_url}")
        
        # Create temporary directory for cloning
        temp_dir = Path(tempfile.mkdtemp(prefix="secagent_repo_"))
        self.temp_dirs.append(temp_dir)
        
        try:
            # Clone repository
            repo = git.Repo.clone_from(git_url, temp_dir)
            
            # Get basic repo info
            try:
                origin_url = repo.remotes.origin.url
                current_branch = repo.active_branch.name
                latest_commit = repo.head.commit.hexsha[:8]
                
                if self.verbose:
                    console.print(f"   Repository: {origin_url}")
                    console.print(f"   Branch: {current_branch}")
                    console.print(f"   Commit: {latest_commit}")
                
                # Save repo metadata
                repo_info = {
                    "source": "git",
                    "url": git_url,
                    "branch": current_branch,
                    "commit": latest_commit,
                    "local_path": str(temp_dir)
                }
                
                import json
                with open(self.run_dir / "repo_info.json", "w") as f:
                    json.dump(repo_info, f, indent=2)
                    
            except Exception as e:
                if self.verbose:
                    console.print(f"   ⚠️  Could not get repo info: {e}", style="yellow")
            
            return temp_dir
            
        except git.GitCommandError as e:
            console.print(f"   ❌ Failed to clone repository: {e}", style="red")
            raise
    
    def _use_local_repo(self, repo_path: str) -> Path:
        """Use local repository path."""
        path = Path(repo_path).resolve()
        
        if not path.exists():
            raise FileNotFoundError(f"Repository path does not exist: {path}")
        
        if not path.is_dir():
            raise NotADirectoryError(f"Repository path is not a directory: {path}")
        
        if self.verbose:
            console.print(f"   Using local repository: {path}")
        
        # Check if it's a Git repository
        git_dir = path / ".git"
        repo_info = {
            "source": "local",
            "path": str(path),
            "is_git": git_dir.exists()
        }
        
        if git_dir.exists():
            try:
                repo = git.Repo(path)
                current_branch = repo.active_branch.name
                latest_commit = repo.head.commit.hexsha[:8]
                
                repo_info.update({
                    "branch": current_branch,
                    "commit": latest_commit
                })
                
                if self.verbose:
                    console.print(f"   Git branch: {current_branch}")
                    console.print(f"   Git commit: {latest_commit}")
                    
            except Exception as e:
                if self.verbose:
                    console.print(f"   ⚠️  Could not read Git info: {e}", style="yellow")
        
        # Save repo metadata
        import json
        with open(self.run_dir / "repo_info.json", "w") as f:
            json.dump(repo_info, f, indent=2)
        
        return path
    
    def cleanup(self):
        """Clean up temporary directories."""
        for temp_dir in self.temp_dirs:
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
        self.temp_dirs.clear()
    
    def __del__(self):
        """Cleanup on deletion."""
        self.cleanup()

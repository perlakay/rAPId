"""
CLI entrypoint for the security agent.
"""

import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, List
import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.text import Text

from .ingest import RepoIngestor
from .normalize import EndpointNormalizer
from .store import SecurityDatabase
from .active import LocalExecutor
from .reporting import ReportRenderer
from .llm.ollama import OllamaClient

app = typer.Typer(help="Local-first codebase+API security agent")
console = Console()

def show_consent_banner() -> bool:
    """Show consent banner and get user confirmation."""
    banner_text = Text()
    banner_text.append("⚠️  SECURITY TESTING CONSENT ⚠️\n\n", style="bold red")
    banner_text.append("This tool performs active security testing against live APIs.\n", style="yellow")
    banner_text.append("• Only test applications and APIs you own or have explicit permission to test\n")
    banner_text.append("• Testing may trigger security alerts or logs in target systems\n")
    banner_text.append("• Use --unsafe flag only when you understand the risks\n")
    banner_text.append("• Results may contain sensitive data - handle reports securely\n\n")
    banner_text.append("By proceeding, you confirm you have proper authorization.", style="bold")
    
    console.print(Panel(banner_text, title="CONSENT REQUIRED", border_style="red"))
    
    return Confirm.ask("Do you have permission to test the target API?", default=False)

@app.command()
def main(
    repo: str = typer.Option(..., "--repo", help="Path to repo or Git URL"),
    base_url: str = typer.Option(..., "--base-url", help="Base URL of API to test"),
    env_file: Optional[str] = typer.Option(None, "--env-file", help="Environment file path"),
    openapi: Optional[str] = typer.Option(None, "--openapi", help="OpenAPI spec file path"),
    graphql_endpoint: Optional[str] = typer.Option(None, "--graphql-endpoint", help="GraphQL endpoint path"),
    auth_header: Optional[str] = typer.Option(None, "--auth-header", help="Authorization header"),
    jwt_hint: str = typer.Option("header", "--jwt-hint", help="JWT location hint: header|cookie|none"),
    unsafe: bool = typer.Option(False, "--unsafe", help="Enable mutating/non-GET requests"),
    concurrency: int = typer.Option(3, "--concurrency", help="Concurrent requests limit"),
    delay_ms: int = typer.Option(200, "--delay-ms", help="Delay between requests (ms)"),
    timeout_ms: int = typer.Option(8000, "--timeout-ms", help="Request timeout (ms)"),
    report: str = typer.Option("both", "--report", help="Report format: md|html|both"),
    ollama_model: str = typer.Option("llama3", "--ollama-model", help="Ollama model name"),
    use_modal: bool = typer.Option(False, "--use-modal", help="Use Modal for distributed cloud testing"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Run codebase+API security analysis."""
    
    # Show consent banner
    if not show_consent_banner():
        console.print("❌ Testing cancelled - consent required", style="red")
        sys.exit(1)
    
    # Create run directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = Path("runs") / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)
    
    console.print(f"🚀 Starting security analysis - Run ID: {timestamp}", style="green bold")
    console.print(f"📁 Artifacts will be saved to: {run_dir}", style="blue")
    
    try:
        # Check if using Modal for distributed testing
        if use_modal:
            console.print("🌩️ Using Modal for distributed cloud testing...", style="magenta bold")
            
            # Import and run Modal execution
            try:
                import sys
                import subprocess
                
                # Run Modal app with parameters
                modal_result = subprocess.run([
                    sys.executable, "modal_app.py",
                    "--repo-url", repo,
                    "--base-url", base_url,
                    "--auth-header", auth_header or "",
                    "--unsafe", str(unsafe).lower(),
                    "--concurrency", str(concurrency),
                    "--delay-ms", str(delay_ms)
                ], capture_output=True, text=True, cwd=Path.cwd())
                
                if modal_result.returncode != 0:
                    console.print(f"❌ Modal execution failed: {modal_result.stderr}", style="red")
                    console.print("🔄 Falling back to local execution...", style="yellow")
                    use_modal = False
                else:
                    console.print("✅ Modal distributed testing completed!", style="green")
                    console.print(modal_result.stdout)
                    return
                    
            except ImportError:
                console.print("❌ Modal not available, falling back to local execution", style="yellow")
                use_modal = False
            except Exception as e:
                console.print(f"❌ Modal execution error: {e}", style="red")
                console.print("🔄 Falling back to local execution...", style="yellow")
                use_modal = False
        
        # Local execution path (original logic)
        # Step 1: Ingest repository
        console.print("\n📥 [1/6] Ingesting repository...", style="cyan bold")
        ingestor = RepoIngestor(run_dir, verbose=verbose)
        repo_path = ingestor.ingest(repo, env_file)
        
        # Step 2: Static discovery
        console.print("\n🔍 [2/6] Discovering endpoints...", style="cyan bold")
        from .discover import StaticDiscovery
        discovery = StaticDiscovery(repo_path, run_dir, verbose=verbose)
        static_results = discovery.discover_all(openapi, graphql_endpoint)
        
        # Step 3: Normalize and store
        console.print("\n📊 [3/6] Normalizing endpoints...", style="cyan bold")
        normalizer = EndpointNormalizer()
        normalized_endpoints = normalizer.normalize(static_results)
        
        db = SecurityDatabase(run_dir / "security.db")
        db.store_endpoints(normalized_endpoints)
        
        # Step 4: Generate test plan
        console.print("\n📋 [4/6] Generating test plan...", style="cyan bold")
        from .active import TestPlanner
        planner = TestPlanner(base_url, auth_header, jwt_hint, unsafe)
        plan = planner.create_plan(normalized_endpoints)
        
        plan_file = run_dir / "plan.jsonl"
        planner.save_plan(plan, plan_file)
        console.print(f"   Generated {len(plan)} test cases")
        
        # Step 5: Execute tests locally
        console.print("\n🧪 [5/6] Executing security tests...", style="cyan bold")
        
        executor = LocalExecutor(
            concurrency=concurrency,
            delay_ms=delay_ms,
            timeout_ms=timeout_ms,
            run_dir=run_dir,
            verbose=verbose
        )
        
        results = executor.execute_plan(plan)
        console.print(f"   Completed {len(results)} tests")
        
        # Step 6: Generate report
        console.print("\n📄 [6/6] Generating report...", style="cyan bold")
        
        # Try to connect to Ollama for enhanced reporting
        ollama_client = None
        try:
            ollama_client = OllamaClient(model=ollama_model)
            if ollama_client.is_available():
                console.print("   🦙 Using Ollama for enhanced reporting")
            else:
                console.print("   ⚠️  Ollama not available - using deterministic reporting")
                ollama_client = None
        except Exception:
            console.print("   ⚠️  Ollama connection failed - using deterministic reporting")
            ollama_client = None
        
        renderer = ReportRenderer(run_dir, ollama_client, verbose=verbose)
        report_files = renderer.generate_reports(
            target_info={
                "repo": repo,
                "base_url": base_url,
                "timestamp": timestamp,
                "run_dir": str(run_dir)
            },
            static_results=static_results,
            endpoints=normalized_endpoints,
            test_results=results,
            report_formats=report.split(",") if "," in report else [report]
        )
        
        # Success summary
        console.print("\n✅ Security analysis complete!", style="green bold")
        console.print(f"📊 Analyzed {len(normalized_endpoints)} endpoints")
        console.print(f"🧪 Executed {len(results)} security tests")
        
        vulnerable_count = sum(1 for r in results if r.get("status") == "vulnerable")
        if vulnerable_count > 0:
            console.print(f"⚠️  Found {vulnerable_count} potential vulnerabilities", style="yellow bold")
        else:
            console.print("🛡️  No obvious vulnerabilities detected", style="green")
        
        console.print(f"\n📄 Reports generated:")
        for report_file in report_files:
            console.print(f"   • {report_file}")
        
        if "html" in report_files[0].suffix:
            console.print(f"\n💡 Open report: open {report_files[0]}")
            
    except KeyboardInterrupt:
        console.print("\n❌ Analysis interrupted by user", style="red")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n❌ Analysis failed: {e}", style="red")
        if verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    app()

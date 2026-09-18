"""Installed root-owned launcher; -I isolates imports from user environments."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from agent_guard.cli import main
raise SystemExit(main())

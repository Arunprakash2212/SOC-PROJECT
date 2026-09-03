"""SOC-PROJECT - a working Security Operations Center pipeline written in plain Python.

Modules are intentionally small and single-purpose so each stage of the SOC workflow can be
run, inspected and argued about on its own:

  telemetry   -> parsers -> detection -> enrich -> cases -> dashboard/report
"""

__version__ = "1.0.0"

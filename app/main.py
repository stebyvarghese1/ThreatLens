"""Main entry point for ThreatLens."""
import sys
from app.core.engine import CoreEngine
from app.gui.app import create_application

def main():
    print("[ThreatLens] Initializing Core Telemetry & Ingestion Engine...", flush=True)
    engine = CoreEngine()
    engine.start()

    print("[ThreatLens] Launching Desktop GUI...", flush=True)
    app, window = create_application(engine)
    window.show()

    try:
        exit_code = app.exec()
    finally:
        print("[ThreatLens] Shutting down monitors and flushing database...", flush=True)
        engine.stop()

    sys.exit(exit_code)


if __name__ == "__main__":
    main()

# 📁 engine/

This folder contains the core logic for rule evaluation and data scanning.

### Subfolders
- `scanner/`: Collect inventory data per cloud service.
- `findings/`: Format and store results, enrich with metadata.
- `utils/`: Helpers like region mappers, error analyzers.

Typical flow: `scanner -> evaluator -> findings -> logs`.
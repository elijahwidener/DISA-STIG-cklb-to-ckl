# DISA-STIG-cklb-to-ckl

Converts STIG Viewer 3.x `.cklb` (JSON) checklists to legacy `.ckl` (XML) format for use with STIG Viewer 2.x and automated tooling.

## Requirements

- Docker, or Python 3.11+

## Usage

### Docker (recommended)

```bash
docker build -t cklb-converter .
docker run --rm -v "/path/to/your/checklists:/data" cklb-converter "your_checklist.cklb"
```

Output is written to the same directory as the input file.

**Windows:**
```powershell
docker run --rm -v "C:\path\to\checklists:/data" cklb-converter "your_checklist.cklb"
```

### Python directly

```bash
python cklb_to_ckl.py your_checklist.cklb
# or with explicit output path
python cklb_to_ckl.py your_checklist.cklb output.ckl
```

### As a module

```python
from cklb_to_ckl import cklb_to_ckl

output_path = cklb_to_ckl("my_checklist.cklb")
output_path = cklb_to_ckl("my_checklist.cklb", "output/my_checklist.ckl")
```

## Notes

- Tested against STIG Viewer 3.x exported `.cklb` files
- Output is compatible with STIG Viewer 2.18
- No third-party dependencies — stdlib only

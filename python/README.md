# Python Security Scripts

## log_analyzer.py
Reads a security log file, identifies failed login attempts, extracts
source IP addresses, and generates a formatted analysis report.

**Usage:**
```
python3 log_analyzer.py                          # sample_auth.log -> analysis_report.txt
python3 log_analyzer.py /var/log/auth.log        # analyze a different log file
python3 log_analyzer.py auth.log -o report.txt   # choose the report file name
python3 log_analyzer.py auth.log -v              # verbose: print every failed login
python3 log_analyzer.py -h                       # show all options
```

| Option | Meaning | Default |
|---|---|---|
| `log_file` | Log to analyze | `sample_auth.log` next to the script |
| `-o`, `--output` | Report file to write | `analysis_report.txt` next to the script |
| `-v`, `--verbose` | List every failed login in the terminal | off |

**Output:** Creates the report file with summary findings. The defaults work from any folder.

**Errors:** If the log file is missing, is a folder, is unreadable or empty, or the report
cannot be written, the script prints a `[!] ERROR` message and exits with code 1.

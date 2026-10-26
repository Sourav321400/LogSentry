# LogSentry
**A Python-based Log Analysis and Anomaly Detection Tool**

LogSentry reads a structured text log, counts event types and IPs, summarizes failed logins using NumPy, and flags users whose total failed logins reach a configurable threshold. This is an educational **rule-based** tool, not a production intrusion detection system.

## Setup and run
```bash
python -m pip install -r requirements.txt
python main.py logs/sample.log
python main.py logs/sample.log --threshold 3 --report reports/summary.csv
python -m unittest discover -v
```
Run commands from the project folder. Tested with Python 3 and NumPy.

## Accepted log format
`YYYY-MM-DD HH:MM:SS EVENT user=NAME ip=ADDRESS`

Supported events: `LOGIN_SUCCESS`, `LOGIN_FAILED`, `ERROR`, `LOGOUT`. Empty lines and comments are ignored; malformed lines are skipped and reported. Example data uses reserved documentation IPs and fictional users.

## NumPy's role
NumPy arrays calculate mean and maximum failed login counts across users with at least one failed login. When there are none, both values are zero.

## Limitations
Alerts count failures across the whole input file, **not** within a time window. Threshold alerts are indicators, not proof of an attack. The parser is for the documented sample format, not arbitrary web/server logs.

## Files
- `main.py`: parser, statistics, alerts, CSV export, command-line interface
- `logs/sample.log`: sample input
- `test_main.py`: automated checks
- `reports/summary.csv`: generated user summary
- `requirements.txt`: NumPy dependency

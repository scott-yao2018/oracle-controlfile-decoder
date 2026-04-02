# Oracle Control File Decoder

A Python tool to decode and analyze Oracle database control files. This utility extracts readable metadata including database information, datafile paths, RMAN backup history, configuration settings, and space allocation analysis without requiring a running Oracle instance.

## Features

- **Database Information**: Extract database name, DBID, and creation timestamps
- **Datafile Analysis**: List all datafiles, tempfiles, and their tablespaces
- **Redo Log Information**: Identify online redo log files
- **RMAN Backup History**: Decode backup pieces, backup sets, and tags
- **Archive Log History**: Find archived redo log entries
- **Pluggable Databases**: Detect CDB$ROOT, PDB$SEED, and PDB information
- **RMAN Configuration**: Extract retention policy, optimization settings, and other configurations
- **Space Allocation Analysis**: Detailed breakdown of control file space usage
- **Feature Detection**: Identify configured Oracle features (RAC, Data Guard, GoldenGate, etc.)

## Requirements

- Python 3.6 or higher
- Read access to Oracle control files

## Installation

```bash
# Clone or download the script
git clone https://github.com/yourusername/oracle-controlfile-decoder.git
cd oracle-controlfile-decoder

# Make executable (optional)
chmod +x decode_controlfile.py
```

## Usage

```bash
python3 decode_controlfile.py <control_file_path>
```

### Examples

```bash
# Decode a control file
python3 decode_controlfile.py /u01/app/oracle/oradata/ORCL/control01.ctl

# Decode a standby control file
python3 decode_controlfile.py /u02/oradata/STBY/control02.ctl

# Save output to file
python3 decode_controlfile.py control01.ctl > control_report.txt
```

## Sample Output

```
======================================================================
ORACLE CONTROL FILE DECODE REPORT
======================================================================

[DATABASE INFORMATION]
  Database Name: TEST
  Control File:  control01.ctl

[CONTAINERS/PLUGGABLE DATABASES]
  - CDB$ROOT
  - PDB$SEED

[DATAFILES]
   1. /u01/app/oracle/oradata/TEST/system01.dbf (SYSTEM)
   2. /u01/app/oracle/oradata/TEST/sysaux01.dbf (SYSAUX)
   ...

[RMAN CONFIGURATION]
  RETENTION POLICY: TO REDUNDANCY 2
  BACKUP OPTIMIZATION: ON
  RMAN OUTPUT: TO KEEP FOR 8 DAYS
  SNAPSHOT CONTROLFILE NAME: /u01/app/oracle/product/19c/dbs/snapcf1.f

[SPACE ALLOCATION ANALYSIS]
  Total File Size: 18,759,680 bytes (17.89 MB)
  Actual Data: 115,200 bytes (0.61%)
  Pre-Allocated: 11,567,104 bytes (61.66%)
  ...
```

## What Gets Decoded

### 1. Database Structure
- Database name and identification
- Container databases (CDB) and pluggable databases (PDB)
- Tablespace names
- Datafile and tempfile locations
- Redo log file configuration

### 2. Backup & Recovery Information
- RMAN backup pieces with file paths
- Backup set metadata and timestamps
- Backup tags
- Archive log history
- Control file autobackup locations

### 3. RMAN Configuration
- Retention policy (REDUNDANCY or RECOVERY WINDOW)
- Backup optimization settings
- Default device type
- Control file autobackup configuration
- Snapshot control file location
- RMAN output retention
- Encryption settings

### 4. Space Analysis
The tool provides detailed space utilization:
- **Actual Data**: Currently used space for records
- **Pre-Allocated**: Reserved slots for future growth
  - Datafile slots (default: 1,024)
  - Redo log slots (default: 512)
  - Backup set slots (default: 4,096)
  - Archived log slots (default: 10,000)
- **True Empty Space**: Unused allocated space

## Why Control Files Are Large

Oracle control files are typically 16-20 MB despite containing only ~100KB of actual data. This is because:

1. **Pre-allocation**: Oracle reserves space for maximum expected database growth
2. **Fixed block structure**: Uses 16KB blocks with pre-assigned record types
3. **Performance**: Avoids file system operations when adding datafiles or backups
4. **Stability**: Prevents file system fragmentation and I/O overhead

## Technical Details

### Record Types Decoded

| Type | Description |
|------|-------------|
| 1 | DATABASE (DB ID/Name) |
| 4 | REDO LOG |
| 5 | DATAFILE |
| 7 | TABLESPACE |
| 10 | ARCHIVED LOG |
| 11 | BACKUP SET |
| 12 | BACKUP PIECE |
| 27 | RMAN CONFIGURATION |
| ... | And more |

## Limitations

- Does NOT decrypt encrypted control files
- Does NOT replace RMAN or SQL queries
- Read-only access (never modifies control files)
- Some binary fields may not be fully decoded
- Obsolete backup status is calculated, not stored

## Safety Notes

⚠️ **Always use copies of control files for analysis, never the live files**

```bash
# Make a copy before analyzing
cp /u01/app/oracle/oradata/ORCL/control01.ctl /tmp/control01_backup.ctl
python3 decode_controlfile.py /tmp/control01_backup.ctl
```

## Contributing

Contributions are welcome! Areas for improvement:
- Support for additional Oracle versions
- Decoding of additional record types
- Export to JSON/XML formats
- Visualization of backup history
- Comparison between control files

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool is for educational and diagnostic purposes. It is not affiliated with Oracle Corporation. Always validate findings against official Oracle documentation and tools (RMAN, SQL queries). Use at your own risk.

## Author

Created for Oracle DBAs who need to understand control file contents without database access.

---

**Note**: This decoder reads metadata only and never modifies control files. For production environments, always work with copies and follow your organization's change management procedures.

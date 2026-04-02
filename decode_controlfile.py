#!/usr/bin/env python3
"""
Oracle Control File Decoder

This script decodes metadata from Oracle database control files.
It extracts readable strings, database information, datafile paths,
redo log files, and other structural information.

Usage:
    python decode_controlfile.py <control_file_path>

Example:
    python decode_controlfile.py /u01/app/oracle/oradata/TEST/control01.ctl
"""

import sys
import struct
import re
from collections import OrderedDict
from datetime import datetime


class OracleControlFileDecoder:
    """Decoder for Oracle control file binary format."""

    # Common Oracle file patterns
    DATAFILE_PATTERNS = [
        r'/[^\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f]+?\.(dbf|ctl|log)',
        r'/[^\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f]+?/arch/[^\x00]+?\.dbf'
    ]

    # Known Oracle tablespace names
    KNOWN_TABLESPACES = [
        'SYSTEM', 'SYSAUX', 'UNDOTBS', 'UNDOTBS1', 'UNDOTBS2',
        'USERS', 'TEMP', 'TEMP1', 'TEMP2', 'RECOVERY'
    ]

    # Known container names
    KNOWN_CONTAINERS = [
        'CDB\$ROOT', 'PDB\$SEED', 'CDB$ROOT', 'PDB$SEED'
    ]

    def __init__(self, filepath):
        self.filepath = filepath
        self.data = None
        self.metadata = {
            'database_name': None,
            'dbid': None,
            'created': None,
            'datafiles': [],
            'tempfiles': [],
            'redologs': [],
            'tablespaces': set(),
            'containers': set(),
            'instances': [],
            'features': set(),
            'archive_logs': [],
            'backup_pieces': [],
            'backup_sets': [],
            'rman_config': {},
            'raw_strings': []
        }

    def read_file(self):
        """Read the control file into memory."""
        try:
            with open(self.filepath, 'rb') as f:
                self.data = f.read()
            print(f"[*] Loaded control file: {self.filepath}")
            print(f"[*] File size: {len(self.data):,} bytes ({len(self.data)/1024/1024:.2f} MB)")
            return True
        except FileNotFoundError:
            print(f"[!] Error: File not found: {self.filepath}")
            return False
        except PermissionError:
            print(f"[!] Error: Permission denied: {self.filepath}")
            return False

    def extract_strings(self, min_length=4):
        """Extract readable ASCII strings from binary data."""
        strings = []
        pattern = re.compile(rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}')

        for match in pattern.finditer(self.data):
            strings.append(match.group().decode('ascii', errors='ignore'))

        self.metadata['raw_strings'] = strings
        return strings

    def find_database_name(self):
        """Extract database name from control file header."""
        # Database name typically appears early in the file
        # Look for uppercase name near standard offsets
        for offset in [0x4020, 0x4024, 0x4000]:
            if offset < len(self.data):
                chunk = self.data[offset:offset+12]
                name = chunk.decode('ascii', errors='ignore').strip('\x00')
                if name and name.isalnum() and len(name) >= 1 and len(name) <= 8:
                    # Verify it's not just random bytes by checking context
                    if offset > 0:
                        prefix = self.data[offset-8:offset]
                        if b'\x00' in prefix or all(b == 0 for b in prefix):
                            self.metadata['database_name'] = name.upper()
                            return name.upper()

        # Fallback: search in strings
        for s in self.metadata['raw_strings']:
            if s.isupper() and 1 <= len(s) <= 8 and s.isalnum():
                if s not in ['SYSTEM', 'SYSAUX', 'UNDOTBS', 'USERS', 'TEMP']:
                    self.metadata['database_name'] = s
                    return s
        return None

    def extract_file_paths(self):
        """Extract datafile, tempfile, and redo log paths."""
        datafiles = []
        tempfiles = []
        redologs = []
        archive_logs = []

        for s in self.metadata['raw_strings']:
            # Check for datafile patterns
            if '.dbf' in s.lower():
                if '/arch/' in s.lower():
                    archive_logs.append(s)
                elif 'temp' in s.lower():
                    if s not in tempfiles:
                        tempfiles.append(s)
                else:
                    if s not in datafiles:
                        datafiles.append(s)

            # Check for redo log files
            elif '.log' in s.lower() and 'redo' in s.lower():
                if s not in redologs:
                    redologs.append(s)

            # Check for control files
            elif '.ctl' in s.lower():
                pass  # Skip control files in the list

        self.metadata['datafiles'] = sorted(set(datafiles))
        self.metadata['tempfiles'] = sorted(set(tempfiles))
        self.metadata['redologs'] = sorted(set(redologs))
        self.metadata['archive_logs'] = sorted(set(archive_logs))

    def extract_tablespaces(self):
        """Identify tablespace names from strings."""
        for s in self.metadata['raw_strings']:
            upper_s = s.upper()
            for ts in self.KNOWN_TABLESPACES:
                if upper_s == ts or upper_s.startswith(ts):
                    self.metadata['tablespaces'].add(upper_s)

    def extract_containers(self):
        """Identify container/pluggable database names."""
        for s in self.metadata['raw_strings']:
            upper_s = s.upper()
            # Look for PDB names and CDB$ROOT, PDB$SEED
            if upper_s in ['CDB$ROOT', 'PDB$SEED']:
                self.metadata['containers'].add(upper_s)
            elif upper_s.startswith('PDB') and upper_s != 'PDB$SEED':
                self.metadata['containers'].add(upper_s)

    def extract_instances(self):
        """Extract instance names."""
        instance_pattern = re.compile(r'UNNAMED_INSTANCE_\d+|^[A-Z][A-Z0-9_$]{0,11}$')
        instances = []

        for s in self.metadata['raw_strings']:
            if 'INSTANCE' in s.upper() or (s.isupper() and s not in self.KNOWN_TABLESPACES):
                if 'UNNAMED_INSTANCE' in s:
                    instances.append(s)

        self.metadata['instances'] = sorted(set(instances))

    def extract_features(self):
        """Extract configured database features."""
        known_features = [
            'GoldenGate', 'Downstream Capture', 'OGG Blocking Mode',
            'RAC', 'RAC-wide SGA', 'Database Guard', 'LSB',
            'Supplemental Log', 'DDL', 'DBMS_ROLLING',
            'PL/SQL quiesce', 'Logical Standby', 'AQ', 'mcache',
            'Active Data Guard', 'Flashback'
        ]

        for s in self.metadata['raw_strings']:
            # Skip file paths
            if '/' in s or '\\' in s or '.dbf' in s or '.log' in s or '.ctl' in s:
                continue
            for feature in known_features:
                if feature.lower() in s.lower():
                    self.metadata['features'].add(s)
                    break

    def extract_rman_config(self):
        """Extract RMAN configuration settings."""
        config = {}

        # Look for RETENTION POLICY
        retention_idx = self.data.find(b'RETENTION POLICY')
        if retention_idx != -1:
            # Look for the value after it
            chunk = self.data[retention_idx:retention_idx+100]
            # Find TO REDUNDANCY or TO RECOVERY WINDOW
            redundancy_match = re.search(rb'TO REDUNDANCY (\d+)', chunk)
            window_match = re.search(rb'TO RECOVERY WINDOW OF (\d+) DAYS?', chunk)

            if redundancy_match:
                config['RETENTION POLICY'] = f'TO REDUNDANCY {redundancy_match.group(1).decode()}'
            elif window_match:
                config['RETENTION POLICY'] = f'TO RECOVERY WINDOW OF {window_match.group(1).decode()} DAYS'
            else:
                config['RETENTION POLICY'] = 'TO NONE (disabled)'

        # Look for DEFAULT DEVICE TYPE
        device_idx = self.data.find(b'DEFAULT DEVICE TYPE')
        if device_idx != -1:
            chunk = self.data[device_idx:device_idx+50]
            if b'TO DISK' in chunk:
                config['DEFAULT DEVICE TYPE'] = 'DISK'
            elif b'TO SBT' in chunk:
                config['DEFAULT DEVICE TYPE'] = 'SBT_TAPE'

        # Look for CONTROLFILE AUTOBACKUP
        autobackup_idx = self.data.find(b'CONTROLFILE AUTOBACKUP')
        if autobackup_idx != -1:
            chunk = self.data[autobackup_idx:autobackup_idx+50]
            if b'ON' in chunk[:30]:
                config['CONTROLFILE AUTOBACKUP'] = 'ON'
            elif b'OFF' in chunk[:30]:
                config['CONTROLFILE AUTOBACKUP'] = 'OFF'

        # Look for BACKUP OPTIMIZATION
        optimization_idx = self.data.find(b'BACKUP OPTIMIZATION')
        if optimization_idx != -1:
            chunk = self.data[optimization_idx:optimization_idx+50]
            if b'ON' in chunk[:30]:
                config['BACKUP OPTIMIZATION'] = 'ON'
            elif b'OFF' in chunk[:30]:
                config['BACKUP OPTIMIZATION'] = 'OFF'

        # Look for ENCRYPTION
        encryption_idx = self.data.find(b'ENCRYPTION')
        if encryption_idx != -1:
            chunk = self.data[encryption_idx:encryption_idx+50]
            if b'ENABLED' in chunk[:30]:
                config['ENCRYPTION'] = 'ENABLED'
            elif b'DISABLED' in chunk[:30]:
                config['ENCRYPTION'] = 'DISABLED'

        # Look for RMAN OUTPUT
        output_idx = self.data.find(b'RMAN OUTPUT')
        if output_idx != -1:
            chunk = self.data[output_idx:output_idx+100]
            # Find TO KEEP FOR X DAYS
            days_match = re.search(rb'TO KEEP FOR (\d+) DAYS', chunk)
            if days_match:
                config['RMAN OUTPUT'] = f"TO KEEP FOR {days_match.group(1).decode()} DAYS"

        # Look for SNAPSHOT CONTROLFILE NAME
        snapshot_idx = self.data.find(b'SNAPSHOT CONTROLFILE NAME')
        if snapshot_idx != -1:
            chunk = self.data[snapshot_idx:snapshot_idx+200]
            # Find path after TO
            path_match = re.search(rb"TO '([^']+)'", chunk)
            if path_match:
                config['SNAPSHOT CONTROLFILE NAME'] = path_match.group(1).decode()

        self.metadata['rman_config'] = config

    def extract_backup_info(self):
        """Extract backup set and backup piece information."""
        backup_pieces = []
        backup_sets = []

        # RMAN backup tags pattern (e.g., TAG20260401T152337)
        tag_pattern = re.compile(r'TAG\d{8}T\d{6}')

        for s in self.metadata['raw_strings']:
            # Look for backup piece files
            # Typical patterns: 01pvhhvp_1_1_1, c-2527584457-20260401-00
            if 'dbs/' in s or 'backup/' in s or 'flashback/' in s:
                if any(ext in s for ext in ['_1_1', '_1_2', 'c-', '.bkp']):
                    if s not in backup_pieces:
                        # Determine backup type from path
                        backup_type = 'Unknown'
                        if 'c-' in s:
                            backup_type = 'Controlfile/Spfile'
                        elif s.count('_') >= 2:
                            backup_type = 'Datafile/Archivelog'

                        backup_pieces.append({
                            'handle': s,
                            'type': backup_type
                        })

            # Look for RMAN tags
            if tag_pattern.match(s):
                backup_sets.append({
                    'tag': s
                })

        self.metadata['backup_pieces'] = backup_pieces
        self.metadata['backup_sets'] = backup_sets

    def extract_timestamp_from_backup(self, stamp):
        """Convert Oracle stamp to readable date."""
        # Oracle stamp is seconds since some epoch, roughly corresponds to
        # 1970-01-01 but with Oracle-specific adjustments
        try:
            # This is a simplified conversion
            from datetime import datetime
            # Oracle stamps from control files are typically based on 1970-01-01
            dt = datetime.fromtimestamp(stamp)
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return 'Unknown'

    def parse_header_info(self):
        """Parse binary header for database metadata."""
        if len(self.data) < 0x4100:
            return

        # Try to extract database ID from header
        # DBID is typically stored at specific offsets
        try:
            # Look at offset 0x4060 area for timestamps and IDs
            chunk = self.data[0x4060:0x4080]
            if len(chunk) >= 16:
                # This might be a timestamp or SCN
                pass
        except:
            pass

    def analyze_record_structure(self):
        """Analyze the record structure in the control file."""
        records = []

        # Oracle control files have records at fixed block boundaries
        # Typically 16KB blocks (0x4000 = 16384 bytes)
        block_size = 0x4000

        for offset in range(0, len(self.data), block_size):
            if offset + 16 > len(self.data):
                break

            # Check for record header pattern
            header = self.data[offset:offset+16]
            if header[0:2] == b'\x00\xc2' or header[0:2] == b'\x15\xc2':
                record_type = struct.unpack('<I', header[4:8])[0] if len(header) >= 8 else 0
                records.append({
                    'offset': hex(offset),
                    'type': record_type,
                    'header': header.hex()
                })

        return records

    def analyze_space_allocation(self):
        """Analyze space allocation in the control file."""
        allocation = {
            'file_size': len(self.data),
            'block_size': 16384,  # 16KB standard
            'total_blocks': len(self.data) // 16384,
            'sections': {},
            'usage_estimate': {}
        }

        # Oracle control file structure (simplified)
        # Block 0: Header
        # Block 1+: Various record sections

        # Analyze different sections based on content patterns
        sections = []

        # Find all record headers
        offset = 0
        while offset < len(self.data) - 16:
            # Check for record header patterns
            header = self.data[offset:offset+16]

            # Type 1: Database record (0x15 c2 pattern)
            if header[0:2] == b'\x15\xc2':
                record_type = struct.unpack('<I', header[4:8])[0] if len(header) >= 8 else 0
                sections.append({
                    'offset': offset,
                    'type': record_type,
                    'desc': self._get_record_type_name(record_type)
                })
                offset += 16384  # Skip to next block
            else:
                offset += 16384

        allocation['sections'] = sections

        # Estimate space usage by content type
        allocation['usage_estimate'] = self._estimate_space_usage()

        return allocation

    def _get_record_type_name(self, record_type):
        """Get human-readable name for record type."""
        type_names = {
            1: 'DATABASE (DB ID/Name)',
            2: 'CKPT PROGRESS',
            3: 'REDO THREAD',
            4: 'REDO LOG',
            5: 'DATAFILE',
            6: 'FILENAME',
            7: 'TABLESPACE',
            8: 'LOG HISTORY',
            9: 'OFFLINE RANGE',
            10: 'ARCHIVED LOG',
            11: 'BACKUP SET',
            12: 'BACKUP PIECE',
            13: 'BACKUP DATAFILE',
            14: 'BACKUP REDO LOG',
            15: 'DATAFILE COPY',
            16: 'BACKUP CORRUPTION',
            17: 'COPY CORRUPTION',
            18: 'DELETED OBJECT',
            19: 'PROXY COPY',
            20: 'BACKUP SPFILE',
            21: 'DATABASE INCARNATION',
            22: 'FLASHBACK LOG',
            23: 'RECOVERY DESTINATION',
            24: 'INSTANCE SPACE RESERVATION',
            25: 'RESERVED2',
            26: 'REMOVABLE RECOVERY FILES',
            27: 'RMAN CONFIGURATION',
            28: 'TABLESPACE KEY HISTORY',
            29: 'TABLESPACE KEY',
            30: 'PDB RECORD',
            31: 'PDB INCARNATION',
            32: 'PDB OPEN HISTORY',
            132: 'RMAN CONFIGURATION (alt)'  # 0x84 = 132
        }
        return type_names.get(record_type, f'Unknown ({record_type})')

    def _estimate_space_usage(self):
        """Estimate space usage by analyzing content."""
        usage = {
            'header': 16384,  # First 16KB block
            'datafile_records': 0,
            'redo_log_records': 0,
            'backup_records': 0,
            'rman_config': 0,
            'other_records': 0,
            'empty_space': 0,
            'pre_allocated': {}
        }

        # Count actual content
        datafile_count = len(self.metadata['datafiles'])
        tempfile_count = len(self.metadata['tempfiles'])
        redolog_count = len(self.metadata['redologs'])
        backup_count = len(self.metadata['backup_pieces'])
        config_count = len(self.metadata['rman_config'])

        # Estimate record sizes (approximate)
        usage['datafile_records'] = (datafile_count + tempfile_count) * 1024  # ~1KB per datafile
        usage['redo_log_records'] = redolog_count * 512
        usage['backup_records'] = backup_count * 2048  # ~2KB per backup
        usage['rman_config'] = config_count * 16384  # Each config in its own block

        # Oracle pre-allocates space for:
        # These are typical default allocations in Oracle control files
        usage['pre_allocated'] = {
            'datafile_slots': {'count': 1024, 'space': 1024 * 1024},      # Space for 1024 datafiles (1MB)
            'redo_log_slots': {'count': 512, 'space': 256 * 1024},        # Space for 512 redo logs (256KB)
            'backup_set_slots': {'count': 4096, 'space': 4 * 1024 * 1024}, # Space for 4096 backup sets (4MB)
            'archived_log_slots': {'count': 10000, 'space': 5 * 1024 * 1024}, # Space for 10000 archivelogs (5MB)
            'config_slots': {'count': 50, 'space': 800 * 1024},            # Space for 50 config records (800KB)
        }

        # Calculate empty space
        used = sum([
            usage['header'],
            usage['datafile_records'],
            usage['redo_log_records'],
            usage['backup_records'],
            usage['rman_config']
        ])
        usage['total_used'] = used

        # Calculate pre-allocated but empty space
        pre_alloc_total = sum(s['space'] for s in usage['pre_allocated'].values())
        usage['pre_allocated_total'] = pre_alloc_total
        usage['empty_space'] = len(self.data) - used - pre_alloc_total
        usage['utilization_percent'] = (used / len(self.data)) * 100
        usage['pre_alloc_percent'] = (pre_alloc_total / len(self.data)) * 100

        return usage

    def decode(self):
        """Run full decoding process."""
        if not self.read_file():
            return False

        print("[*] Extracting strings...")
        self.extract_strings()

        print("[*] Parsing database name...")
        self.find_database_name()

        print("[*] Extracting file paths...")
        self.extract_file_paths()

        print("[*] Identifying tablespaces...")
        self.extract_tablespaces()

        print("[*] Identifying containers...")
        self.extract_containers()

        print("[*] Extracting instance information...")
        self.extract_instances()

        print("[*] Identifying features...")
        self.extract_features()

        print("[*] Extracting backup information...")
        self.extract_backup_info()

        print("[*] Extracting RMAN configuration...")
        self.extract_rman_config()

        print("[*] Analyzing space allocation...")
        self.space_allocation = self.analyze_space_allocation()

        print("[*] Parsing header...")
        self.parse_header_info()

        return True

    def print_report(self):
        """Print formatted report of decoded information."""
        print("\n" + "="*70)
        print("ORACLE CONTROL FILE DECODE REPORT")
        print("="*70)

        # Database Information
        print("\n[DATABASE INFORMATION]")
        print(f"  Database Name: {self.metadata['database_name'] or 'Not found'}")
        print(f"  Control File:  {self.filepath}")

        # Containers
        if self.metadata['containers']:
            print("\n[CONTAINERS/PLUGGABLE DATABASES]")
            for container in sorted(self.metadata['containers']):
                print(f"  - {container}")

        # Datafiles
        if self.metadata['datafiles']:
            print("\n[DATAFILES]")
            for i, df in enumerate(self.metadata['datafiles'], 1):
                # Identify tablespace from path
                ts_name = None
                for ts in self.metadata['tablespaces']:
                    if ts.lower() in df.lower():
                        ts_name = ts
                        break
                ts_str = f" ({ts_name})" if ts_name else ""
                print(f"  {i:2}. {df}{ts_str}")

        # Tempfiles
        if self.metadata['tempfiles']:
            print("\n[TEMPFILES]")
            for i, tf in enumerate(self.metadata['tempfiles'], 1):
                print(f"  {i:2}. {tf}")

        # Redo Logs
        if self.metadata['redologs']:
            print("\n[REDO LOG FILES]")
            for i, rl in enumerate(self.metadata['redologs'], 1):
                print(f"  {i:2}. {rl}")

        # Archive Logs
        if self.metadata['archive_logs']:
            print("\n[ARCHIVE LOGS (Historical)]")
            for i, al in enumerate(self.metadata['archive_logs'][:10], 1):
                print(f"  {i:2}. {al}")
            if len(self.metadata['archive_logs']) > 10:
                print(f"  ... and {len(self.metadata['archive_logs']) - 10} more")

        # Tablespaces
        if self.metadata['tablespaces']:
            print("\n[TABLESPACES]")
            for ts in sorted(self.metadata['tablespaces']):
                print(f"  - {ts}")

        # Instances
        if self.metadata['instances']:
            print("\n[INSTANCE INFORMATION]")
            for inst in self.metadata['instances'][:10]:
                print(f"  - {inst}")

        # Features
        if self.metadata['features']:
            print("\n[CONFIGURED FEATURES]")
            for feature in sorted(self.metadata['features']):
                print(f"  - {feature}")

        # Backup Information
        if self.metadata['backup_pieces']:
            print("\n[RMAN BACKUP PIECES]")
            for i, bp in enumerate(self.metadata['backup_pieces'], 1):
                print(f"  {i:2}. {bp['handle']}")
                print(f"      Type: {bp['type']}")

        if self.metadata['backup_sets']:
            print("\n[RMAN BACKUP TAGS]")
            for bs in self.metadata['backup_sets']:
                print(f"  - {bs['tag']}")

        # RMAN Configuration
        if self.metadata['rman_config']:
            print("\n[RMAN CONFIGURATION]")
            for key, value in self.metadata['rman_config'].items():
                print(f"  {key}: {value}")

        # Space Allocation Analysis
        if hasattr(self, 'space_allocation'):
            print("\n[SPACE ALLOCATION ANALYSIS]")
            alloc = self.space_allocation
            usage = alloc['usage_estimate']

            print(f"  Total File Size: {alloc['file_size']:,} bytes ({alloc['file_size']/1024/1024:.2f} MB)")
            print(f"  Block Size: {alloc['block_size']:,} bytes ({alloc['block_size']/1024} KB)")
            print(f"  Total Blocks: {alloc['total_blocks']:,}")
            print()
            print("  Actual Data Usage:")
            print(f"    Header Block:            {usage['header']:>12,} bytes ({usage['header']/1024:>8.1f} KB)")
            print(f"    Datafile Records:        {usage['datafile_records']:>12,} bytes ({usage['datafile_records']/1024:>8.1f} KB) [{len(self.metadata['datafiles'])+len(self.metadata['tempfiles'])} files]")
            print(f"    Redo Log Records:        {usage['redo_log_records']:>12,} bytes ({usage['redo_log_records']/1024:>8.1f} KB) [{len(self.metadata['redologs'])} files]")
            print(f"    Backup Records:          {usage['backup_records']:>12,} bytes ({usage['backup_records']/1024:>8.1f} KB) [{len(self.metadata['backup_pieces'])} pieces]")
            print(f"    RMAN Config Records:     {usage['rman_config']:>12,} bytes ({usage['rman_config']/1024:>8.1f} KB) [{len(self.metadata['rman_config'])} configs]")
            print(f"    {'─'*50}")
            print(f"    Subtotal Actual Data:    {usage['total_used']:>12,} bytes ({usage['total_used']/1024:>8.1f} KB)")
            print()
            print("  Pre-Allocated Space (Reserved for Future Growth):")
            for name, info in usage['pre_allocated'].items():
                print(f"    {name.replace('_', ' ').title():<25} {info['space']:>12,} bytes ({info['space']/1024:>8.1f} KB) [{info['count']:,} slots]")
            print(f"    {'─'*50}")
            print(f"    Subtotal Pre-Allocated:  {usage['pre_allocated_total']:>12,} bytes ({usage['pre_allocated_total']/1024:>8.1f} KB)")
            print()
            print("  Summary:")
            print(f"    Actual Data:             {usage['total_used']:>12,} bytes ({usage['total_used']/1024:>8.1f} KB) [{usage['utilization_percent']:>5.2f}%]")
            print(f"    Pre-Allocated:           {usage['pre_allocated_total']:>12,} bytes ({usage['pre_allocated_total']/1024:>8.1f} KB) [{usage['pre_alloc_percent']:>5.2f}%]")
            print(f"    True Empty Space:        {usage['empty_space']:>12,} bytes ({usage['empty_space']/1024:>8.1f} KB)")
            print()
            print("  Note: Oracle pre-allocates control file space to avoid resizing.")
            print("        Pre-allocated slots are reserved for future datafiles, redo logs,")
            print("        backup sets, and archived logs without file system operations.")

        print("\n" + "="*70)
        print("END OF REPORT")
        print("="*70)


def main():
    if len(sys.argv) < 2:
        print("Oracle Control File Decoder")
        print(f"Usage: {sys.argv[0]} <control_file_path>")
        print(f"\nExample:")
        print(f"  {sys.argv[0]} /u01/app/oracle/oradata/ORCL/control01.ctl")
        sys.exit(1)

    control_file = sys.argv[1]

    decoder = OracleControlFileDecoder(control_file)
    if decoder.decode():
        decoder.print_report()
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()

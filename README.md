<<<<<<< HEAD
# V1FS-GO-Scanner
V1FS-GO-Scanner

Build Binary: <br>
`go build main.go`


Example Usage:</br>
`./main -apiKey=$apiKey -region=$region -directory="/Users/hunter/Desktop/test" -tags=project1,test -verbose=true -maxWorkers=2`
=======
# Vision One File Security Go Scanner

The scanner is a Go binary designed to function as a command-line program. It recursively scans all items in a given directory path with advanced optimization features for large-scale scanning operations, including checkpoint recovery for interrupted scans.

## SDK Reference
Link to Github SDK Repo: https://github.com/trendmicro/tm-v1-fs-golang-sdk

## Parameters

### Required Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| -apiKey | string | Vision One API Key (can also use V1_FS_KEY environment variable) |
| -directory | string | Path to directory to scan recursively |

### Basic Configuration
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| -maxWorkers | int | 100 | Max number of concurrent file scans |
| -region | string | "us-east-1" | Vision One Region |
| -tags | string | "" | Up to 8 comma-separated strings |
| -verbose | bool | false | Log all scans to stdout |
| -exclude-dir | string | "" | Path to file containing directories to exclude |
| -internal_address | string | "" | Internal Service Gateway Address |
| -internal_service | string | "default" | Internal service name |
| -internal_tls | bool | true | Use TLS for internal Service Gateway |

### Performance Optimization
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| -maxFileSize | int64 | 500MB | Maximum file size to scan (in bytes) |
| -minFileSize | int64 | 1KB | Minimum file size to scan (in bytes) |
| -maxMemoryMB | int64 | 1024 | Maximum memory usage in MB |
| -iothrottle | int | 0 | Milliseconds to wait between file operations |
| -skipExt | string | ".iso,.vmdk,.vdi,.dll" | Comma-separated list of file extensions to skip |

### Feature Flags
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| -pml | bool | false | Enable predictive machine learning detection |
| -feedback | bool | false | Enable Smart Protection Network feedback |

## Output Files
The program creates the following files in its running directory:
| Filename | Description |
|----------|-------------|
| "{timestamp}-Scan.log" | Documents total files scanned, scan results, and execution time |
| "{timestamp}.error.log" | Logs any file scan errors |
| "scan_checkpoint.json" | Stores scan progress for recovery from interruptions |

## Checkpoint Recovery
The scanner implements automatic checkpoint recovery with the following features:
- Creates checkpoints every 5 minutes during scanning
- Saves the last scanned directory path and total files processed
- Automatically resumes from last checkpoint if scan is interrupted
- Checkpoint data is stored in `scan_checkpoint.json`

## Performance Tips

### Memory Management
- The scanner includes automatic memory monitoring
- Pauses scanning when memory usage exceeds `-maxMemoryMB`
- Resumes when memory usage drops below 80% of limit
- For large scans, consider setting `-maxMemoryMB=4096` or higher

### IO Throttling
- Use `-iothrottle` to prevent I/O saturation
- Recommended values:
  - Local SSD: 0-1ms
  - Network storage: 5-10ms
  - High latency storage: 10-20ms

### Worker Pool Optimization
- Default 100 concurrent workers
- Adjust based on:
  - Available CPU cores
  - Storage I/O capacity
  - Network bandwidth (for remote storage)
- For local SSDs, try 200-300 workers
- For network storage, reduce to 50-100

### Example Configurations

#### Basic Usage
```sh
./v1_fs_scanner_linux -apiKey=<v1_api_key> -directory=/tmp/some_folder
```

#### Optimized for Large Volumes
```sh
./v1_fs_scanner_linux \
  -apiKey=$TMAS_API_KEY \
  -directory=/data \
  -maxWorkers=150 \
  -maxMemoryMB=4096 \
  -maxFileSize=50000000 \
  -minFileSize=1000 \
  -skipExt=".iso,.vmdk,.vdi,.dll,.exe,.bak,.tmp" \
  -iothrottle=1 \
  -verbose=true \
  -tags=dev,us-east-1,temp_project \
  -exclude-dir=exclusions.txt
```

#### Using Internal Gateway
```sh
./v1_fs_scanner_linux \
  -apiKey=$TMAS_API_KEY \
  -directory=/data \
  -internal_address="gateway.internal" \
  -internal_service="fs-service" \
  -internal_tls=true
```
>>>>>>> b83e2c0 (add checkpoint recovery and improve scanner robustness)

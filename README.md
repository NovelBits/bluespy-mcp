# BlueSPY MCP Server

MCP server for the [BlueSPY](https://rfcreations.com) Bluetooth LE protocol analyzer. Load and analyze .pcapng capture files from BlueSPY sniffers using AI assistants like Claude Desktop, Claude Code, and Cursor.

## Prerequisites

- **Python 3.10+**
- **BlueSPY application** installed from [rfcreations.com](https://rfcreations.com) (provides the native `libblueSPY` library)

## Installation

```bash
pip install bluespy-mcp
```

Or install from source:

```bash
git clone https://github.com/novelbits/bluespy-mcp.git
cd bluespy-mcp
pip install .
```

## Configuration

### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "bluespy": {
      "command": "bluespy-mcp",
      "env": {
        "BLUESPY_LIBRARY_PATH": "/Applications/blueSPY.app/Contents/Frameworks/libblueSPY.dylib"
      }
    }
  }
}
```

### Claude Code

Add to your `.mcp.json`:

```json
{
  "bluespy": {
    "command": "bluespy-mcp",
    "env": {
      "BLUESPY_LIBRARY_PATH": "/Applications/blueSPY.app/Contents/Frameworks/libblueSPY.dylib"
    }
  }
}
```

### Cursor

Add to your MCP server configuration:

```json
{
  "bluespy": {
    "command": "bluespy-mcp",
    "env": {
      "BLUESPY_LIBRARY_PATH": "/Applications/blueSPY.app/Contents/Frameworks/libblueSPY.dylib"
    }
  }
}
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `BLUESPY_LIBRARY_PATH` | Path to `libblueSPY.dylib` / `.so` / `.dll` | Yes |
| `BLUESPY_API_PATH` | Path to directory containing `bluespy.py` (auto-discovered if not set) | No |
| `BLE_CAPTURES_DIR` | Default directory for capture files (default: `captures/`) | No |

### Platform-Specific Library Paths

**macOS:**
```
/Applications/blueSPY.app/Contents/Frameworks/libblueSPY.dylib
```

**Windows:**
```
C:\Program Files\blueSPY\libblueSPY.dll
```

**Linux:**
```
/usr/local/lib/libblueSPY.so
```

## Tools

### File Management

| Tool | Description |
|------|-------------|
| `load_capture(file_path)` | Load a .pcapng capture file for analysis |
| `close_capture()` | Close the currently loaded file |
| `list_captures(directory?)` | List .pcapng files in a directory |

### Discovery

| Tool | Description |
|------|-------------|
| `capture_summary()` | Packet counts by type, duration, device/connection counts |
| `list_devices()` | All Bluetooth devices with addresses and names |
| `list_connections()` | All connections with parameters (interval, latency, timeout) |

### Analysis

| Tool | Description |
|------|-------------|
| `search_packets(summary_contains?, packet_type?, channel?, max_results?)` | Filter packets by criteria |
| `inspect_connection(connection_index)` | Connection parameters and packet breakdown |
| `inspect_advertising(device_index)` | Advertising data, RSSI, channels for a device |
| `find_capture_errors(max_results?)` | Error, failure, disconnect, and timeout packets |

### Resources

| Resource | Description |
|----------|-------------|
| `capture://status` | Current loaded file metadata (JSON) |

## Example Usage

After configuring your MCP client, you can ask:

- "Load my capture file at ~/captures/ble_test.pcapng"
- "Give me a summary of this capture"
- "Show me all the advertising packets"
- "Find any errors or disconnections"
- "Analyze the first connection"
- "Search for ATT packets"

## Troubleshooting

### "BlueSPY library not found"

Ensure `BLUESPY_LIBRARY_PATH` points to the correct native library for your platform. The BlueSPY application must be installed.

### "No capture file loaded"

Use `load_capture()` with a path to your .pcapng file before calling analysis tools.

### Module not found errors

Ensure you're using Python 3.10+ and have installed the package:

```bash
python --version  # Should be 3.10+
pip install bluespy-mcp
```

## License

MIT License. See [LICENSE](LICENSE) for details.

## Links

- [BlueSPY by RFcreations](https://rfcreations.com)
- [MCP Protocol](https://modelcontextprotocol.io)
- [Issues](https://github.com/novelbits/bluespy-mcp/issues)

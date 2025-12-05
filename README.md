# afFIRM: Automated firmware emulation powered by MCP

**afFIRM** is a command-line tool and Model Context Protocol (MCP) server that provides a powerful automation and management layer on top of the [FirmAE](https://github.com/pr0v3rbs/FirmAE) firmware emulation framework and the `emux` emulation tool. It is designed to streamline the process of firmware analysis, from acquisition and emulation to failure analysis and results tracking.

This tool allows a user to interact with FirmAE and emux programmatically, making it ideal for automated security testing, large-scale analysis, and integration into larger analysis pipelines.

## Key Features

- **Firmware Emulation**: Programmatically run firmware emulation using FirmAE for a variety of hardware brands.
- **Automated Failure Analysis**: If an emulation fails, `afFIRM` automatically analyzes the logs to provide heuristic-based reasons for the failure, speeding up the debugging process.
- **Firmware Acquisition**: Search for and download firmware directly from vendor websites (e.g., TP-Link).
- **Emulation History**: Keeps a persistent record of all emulation attempts, their parameters, and their outcomes in a CSV file for easy review.
- **Knowledge Base**: Stores detailed run information and analysis results in a SQLite database, creating a knowledge base of successful and failed emulations.
- **`emux` Integration**:
    - **Build Custom Environments**: Prepare custom firmware emulation environments for `emux` from a template, including kernel selection, rootfs packaging, and configuration.
    - **Manage Configurations**: Dynamically add or update device configurations for `emux`.
    - **Rebuild Environment**: Automate the rebuilding of the `emux` Docker and volume setup.
- **MCP Server**: Exposes its functionality through a Model Context Protocol, allowing it to be controlled by other tools and services.

## Available Tools

The following tools are exposed via the MCP interface:

### FirmAE Tools (`firmae.*`)

- `firmae.help`: Displays detailed help and usage information.
- `firmae.emulate`: Emulates a given firmware file for a specific brand.
- `firmae.clean`: Cleans the FirmAE `scratch` directory.
- `firmae.search`: Searches for and optionally downloads firmware for a given brand and model.
- `firmae.lookupKB`: Lists supported models from the local knowledge base.
- `firmae.history`: Displays a history of past emulation runs with filtering capabilities.

### emux Tools (`emux.*`)

- `emux.emuxbuild`: Creates a new `emux` firmware directory from a template, preparing it for emulation.
- `emux.applyconfig`: Adds or updates a device configuration row in the `emux` devices file.
- `emux.rebuild`: Rebuilds the `emux` Docker environment.

## Getting Started

This project is intended to be run as an MCP server. A client capable of sending MCP requests is required to interact with it. The server is implemented in `firmae_mcp.py`.

1.  **Prerequisites**:
    - A working installation of [FirmAE](https://github.com/pr0v3rbs/FirmAE).
    - A working installation of `emux`.
    - Python 3 and the packages listed in `requirements.txt`.

2.  **Configuration**:
    - Set the `FIRMAE_HOME` environment variable to the path of your FirmAE installation.
    - Set the `EMUX_HOME` environment variable to the path of your `emux` installation.

3.  **Running the server**:
    ```bash
    sudo ./mcphost --config config.json
    ```

4.  **Interacting with the server**:
    - Use an MCP client to send tool calls. For example, to emulate a firmware (can also use natural language instead of JSON-prettify):
    ```json
    {
      "tool_code": "handle_call({\"name\": \"firmae.emulate\", \"arguments\": {\"brand\": \"TPLINK\", \"firmware_file\": \"/path/to/firmware.bin\"}})"
    }
    ```

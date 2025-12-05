#!/usr/bin/env python3

def list_tools():
    return {
        "tools": [
            {
                "name": "firmae.help",
                "description": "Show how to use FirmAE MCP tools with examples.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "firmae.emulate",
                "description": "Run FirmAE emulation for a given firmware image.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "brand": {"type": "string", "description": "Brand name (e.g., DLINK)"},
                        "firmware_file": {"type": "string", "description": "Firmware filename or full path"},
                        "timeout": {"type": "integer", "description": "Timeout (seconds). Default 1800."}
                    },
                    "required": ["brand", "firmware_file"]
                }
            },
            {
                "name": "firmae.clean",
                "description": "Clear all folders inside ~/FirmAE/scratch/",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "firmae.search",
                "description": "Search and download firmware images by brand and model.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "brand": {"type": "string", "description": "Brand name (e.g., DLINK)"},
                        "model": {"type": "string", "description": "Model or keyword (e.g., DIR-868L)"},
                        "download": {"type": "boolean", "description": "If true, download the selected firmware."}
                    },
                    "required": ["brand", "model"]
                }
            },
            {
                "name": "firmae.lookupKB",
                "description": "Display a list of known  router models available for firmware lookup.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "firmae.history",
                "description": "View past emulation records from emulation_records.csv with optional filters.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                    "brand": {"type": "string", "description": "Filter by brand (e.g., DLINK, TPLINK)"},
                        "model": {"type": "string", "description": "Substring match against firmware_name"},
                        "success_only": {"type": "boolean", "description": "Show only successful runs"},
                        "last_n": {"type": "integer", "description": "Limit to the most-recent N rows (by number). Default 20"}
                        }
                }
            },
            {
                "name": "emux.emuxbuild",
                "description": "Scaffold an EMUX device folder from template, copy a firmware image, tar the extracted rootfs, and set the kernel (from template or a custom path). Optionally set nvram.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                    "firmware_model": {
                        "type": "string",
                        "description": "Model name (e.g., DIR-868L or Archer C7). Becomes destination folder name."
                    },
                    "firmware_image": {
                        "type": "string",
                        "description": "Absolute or relative path to the firmware image (.zip, .bin, etc.). Required."
                    },
                    "kernel_choice": {
                        "type": "string",
                        "description": "Filename from EMUX template/kernel (e.g., zImage-2.6.31.14-realview-rv130-nothumb). Provide this OR kernel_path."
                    },
                    "kernel_path": {
                        "type": "string",
                        "description": "Absolute/relative path to a custom kernel file. Provide this OR kernel_choice."
                    },
                    "nvram_path": {
                        "type": "string",
                        "description": "Optional path to nvram.ini. If omitted, the nvram line in config is commented."
                    }
                    },
                    "required": ["firmware_model", "firmware_image"]
                }
            },
            {
                "name": "emux.applyconfig",
                "description": "Append or update a device row in EMUX files/emux/devices (or devices-extra). Accepts a full CSV row or structured fields.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "devices_target": {
                            "type": "string",
                            "description": "Which devices file to modify: 'devices' (default) or 'devices-extra'."
                        },
                        "row": {
                            "type": "string",
                            "description": "Full CSV row to write (as printed by emuxbuild suggestion). If omitted, provide 'fields'."
                        },
                        "fields": {
                            "type": "object",
                            "description": "Structured fields if 'row' is not provided.",
                            "properties": {
                            "ID": { "type": "string" },
                            "qemu-binary": { "type": "string" },
                            "machine-type": { "type": "string" },
                            "cpu-type": { "type": "string" },
                            "dtb": { "type": "string" },
                            "memory": { "type": "string" },
                            "kernel-image": { "type": "string" },
                            "qemuopts": { "type": "string" },
                            "description": { "type": "string" }
                            }
                        },
                        "allow_update": {
                            "type": "boolean",
                            "description": "If true (default), update existing row with same ID; otherwise always append."
                        },
                        "create_backup": {
                            "type": "boolean",
                            "description": "If true (default), create a timestamped .bak before writing."
                        }
                    }
                }
            },
            {
                "name": "emux.rebuild",
                "description": "Rebuild the EMUX environment by running build-emux-volume and build-emux-docker inside EMUX_HOME. Waits for both steps to finish and returns full logs.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                    "timeout_sec": {
                        "type": "integer",
                        "description": "Max seconds allowed for each step (volume/docker). Default: 7200 (2 hours)."
                    },
                    "no_sudo": {
                        "type": "boolean",
                        "description": "Run without sudo (set true if your environment doesn’t require sudo). Default: false."
                    }
                    }
                }
            }
        ]
    }


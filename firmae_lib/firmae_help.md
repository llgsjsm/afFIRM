# afFIRM — quick guide

Tools:
• **firmae.help**  
  Show this help.

• **firmae.emulate** `{brand, firmware_file, [timeout], [wait_seconds]}`
  Run FirmAE: `./run.sh -c <brand> <firmware_path>`.
  - `firmware_file` can be absolute or relative to {FIRMAE_HOME}
  - `wait_seconds` (default = `timeout`) waits for `scratch/<iid>/result`
  Example:
    brand: "DLINK", firmware_file: "{FIRMAE_HOME}/firmware/DIR-868L_fw_revB_2-05b02_eu_multi_20161117.zip"

• **firmae.clean**  
  Wipe `{FIRMAE_HOME}/scratch/*`

• **firmae.search** `{brand, model, [download], [selection_index]}`
  1) First call with brand+model to list.
  2) Call again with `download=true` and `selection_index=N` to download.
  Example:
    brand: "TPLINK", model: "Archer C7"        # list
    brand: "TPLINK", model: "Archer C7", download: true, selection_index: 1

• **firmae.lookupKB** `{[brand], [model]|[query]}`
  - No args: prints TP-Link KB from `tplink-kb` (same dir).
  - With brand/model: show KB matches (TP-Link) + emulation records (CSV).
  Example:
    { "brand":"DLINK", "model":"DIR-868L" }

• **firmae.history** `{[brand], [model], [success_only], [last_n]}`
  Inspect `emulation_records.csv`.

• **emux.emuxbuild** `{firmware_model, firmware_image, (kernel_choice|kernel_path), [nvram_path]}`
Scaffold an EMUX device folder from template, stage firmware, extract rootfs, and suggest a `devices` row.

* Copies template → `{EMUX_HOME}/files/emux/firmware/<MODEL>` (adds `-2`, `-3`… if exists)
* Updates `config`: sets `id=firmware/<folder>`, sets or comments `nvram=`
* Stages firmware image; if `.zip`, extracts; runs `binwalk -e` on found images
* Finds `squashfs-root`/`cramfs-root` recursively and creates `rootfs.tar.bz2`
* Kernel is **required**: use `kernel_choice` from `template/kernel/` **or** `kernel_path` to a file
* Prints a suggested CSV row for `files/emux/firmware/devices`
  Example:
  `firmware_model: "DIR-868L", firmware_image: "/tmp/DIR868L.bin", kernel_choice: "zImage-3.16.57-vexpress"`

• **emux.applyconfig** `{[devices_target], row | fields, [allow_update], [create_backup]}`
Append/update a device CSV row into `files/emux/firmware/<devices_target>`.

* `devices_target`: `"devices"` (default) or `"devices-extra"`
* Provide either a full CSV `row` string **or** a `fields` object with all columns:
  `ID,qemu-binary,machine-type,cpu-type,dtb,memory,kernel-image,qemuopts,description`
* `allow_update` (default `true`): replace existing row by same `ID`
* `create_backup` (default `true`): saves `.bak.<timestamp>` before writing
  Examples:
* Using `row`:
  `devices_target: "devices", row: "firmware/DIR-868L,qemu-system-arm,vexpress-a9,,,...,DIR-868L (suggested)"`
* Using `fields`:
  `{ devices_target: "devices-extra", fields: { "ID":"firmware/DIR-868L", "qemu-binary":"qemu-system-arm", ... } }`

• **emux.rebuild** `{[timeout_sec], [no_sudo]}`
Rebuild EMUX artifacts by running in `{EMUX_HOME}`:

1. `sudo ./build-emux-volume` → 2. `sudo ./build-emux-docker`

* `timeout_sec`: overall per-step timeout (default `7200`)
* `no_sudo`: set `true` to run without `sudo` (helpful if NOPASSWD/TTY issues)
* Returns stdout/stderr, exit codes, and durations for both steps
  Example:
  `timeout_sec: 5400, no_sudo: false`


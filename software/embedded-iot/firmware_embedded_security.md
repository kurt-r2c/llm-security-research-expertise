# Firmware and Embedded Systems Security
## Staff-Level Technical Reference

---

## I. Researcher Profiles

### Ang Cui — Red Balloon Security

**Career arc**: B.S. and Ph.D. Columbia University (IDS Lab, advisor Salvatore Stolfo); dissertation: "Embedded System Security: A Software-Based Approach" (2015) — the definitive early academic treatment of large-scale firmware vulnerability measurement and source-code-independent firmware defense. Co-founded Red Balloon Security in 2011 while still a doctoral candidate; commercialized Symbiote technology. Now CEO of Red Balloon Security, consulting for critical infrastructure, DoD/DHA, and ICS/SCADA environments.

**Core research arc**: firmware vulnerability measurement at scale → firmware defense (Symbiote, ABSR) → full-spectrum embedded exploitation (firmware worms, lateral movement across heterogeneous embedded populations) → hardware root of trust attacks (Thrangrycat, CVE-2019-1649) → EM covert channels (Funtenna) → hardware-level attacks against air-gapped systems (EMFI, cryo-mechanical RAM extraction).

**Tools**:
- **FRAK (Firmware Reverse Analysis Konsole)**: original internal framework for unpacking, analyzing, modifying, and repacking proprietary embedded firmware. Demonstrated at DEF CON 20 (2012) on Cisco IOS, Cisco IP phones, HP LaserJets.
- **OFRAK (Open Firmware Reverse Analysis Konsole)**: FRAK's source-available successor (August 2022, DARPA/DoD funding). Source-available under OFRAK Community License. Key capabilities: recursive identification, unpacking, and repacking of nested firmware structures (ELF inside XZ-compressed CPIO inside ISO); Python API for reproducible scripting; integrated with angr, Binary Ninja, Ghidra, IDA Pro; web GUI with navigable resource tree, entropy/byteclass/magnitude minimap. Supports: UEFI, Linux kernel images, squashfs, ext2/3/4, JFFS2, LZMA/XZ, gzip, zlib, ZIP, CPIO, ELF, PE, Mach-O.
- **Symbiote**: binary host-based IDS injected into firmware at runtime without device source code or manufacturer cooperation. Checks integrity of static code and data continuously. Works at binary level on MIPS and ARM. Commercially licensed to HP for use in HP printers.
- **badFET**: low-cost programmable EM fault injection (EMFI) pulse generator.

**Key publications**:
- "Defending Embedded Systems with Software Symbiotes" (RAID 2011) — first Symbiote publication
- "When Firmware Modifications Attack: A Case Study of Embedded Exploitation" (NDSS 2013)
- "BADFET: Defeating Modern Secure Boot Using Second-Order Pulsed Electromagnetic Fault Injection" (USENIX WOOT 2017, with Rick Housley) — second-order EMFI: pulses targeted at peripheral conductors (power delivery traces, peripheral buses) rather than CPU; induced currents propagate to CPU via board interconnects; defeats ARM TrustZone secure boot on Cisco 8861 (Broadcom BCM11123 SoC)
- "Cryo-Mechanical RAM Content Extraction Against Modern Embedded Systems" (USENIX WOOT / IEEE S&P 2023, with Grant Skipper and Yuanzhe Wu) — ~$500 AliExpress CNC machine (~$2,000 total build) + FPGA DDR3 reader + ESP32 controller; cools DDR3 chips below data-retention threshold (~-50°C), reads out full RAM contents before thermal equilibration; demonstrated on Siemens S7-1500 PLC (extracted encrypted firmware from runtime memory) and Cisco IP Phone 8800 (read TrustZone secure world memory)

**CVEs**: CVE-2012-5445 (Cisco 7900 IP Phone kernel syscall local privilege escalation); CVE-2019-1649 (Thrangrycat — Cisco Trust Anchor FPGA bitstream manipulation)

**Talk list** (selected):
| Year | Conference | Title |
|------|------------|-------|
| 2023 | REcon / Summercon | Ice Ice Baby: Coppin' RAM With DIY Cryo-Mechanical Robot |
| 2019 | DEF CON 27 / Black Hat USA | 100 Seconds of Solitude: Defeating Cisco Trust Anchor With FPGA Bitstream Shenanigans |
| 2017 | Summercon | ZapZap! bangBang! (expanded EMFI) |
| 2016 | DEF CON 24 / REcon | A Monitor Darkly: Reversing OSD Controllers in Modern Monitors |
| 2015 | Black Hat USA | Emanate Like a Boss: Generalized Covert Data Exfiltration with Funtenna |
| 2013 | DEF CON 21 / Black Hat USA | Stepping P3wns: Full Spectrum Embedded Exploitation and Defense |
| 2012 | DEF CON 20 | Embedded Device Firmware Vulnerability Hunting Using FRAK |
| 2011 | Black Hat USA | Killing the Myth of Cisco IOS Diversity |

**Talk highlights**:
- *Stepping P3wns (DC21 2013)*: live demo of embedded firmware worm with autonomous polyspecies propagation across Cisco IP phones, HP LaserJets, Cisco routers via ≥1 0-day + known vulnerabilities; stealthy C2 over legitimate protocols; Symbiote-based defense in same firmware images
- *A Monitor Darkly (DC24 2016)*: OSD controllers in Dell/HP/Samsung/Acer monitors are full ARM Cortex-M microcontrollers with SPI flash; can read pixel data, modify arbitrary pixels, execute arbitrary code; attack via USB DDC/CI or VGA/HDMI update path; affects ~1 billion monitors
- *Funtenna (BH 2015)*: software-only covert exfiltration by rapidly toggling GPIO/PWM/UART TX pins to generate modulated RF signals; Pantum printer antenna → signal received through reinforced concrete outside building

---

### Travis Goodspeed

**Career arc**: Independent researcher based in Tennessee. Self-taught hardware hacker specializing in microcontroller firmware, embedded wireless protocols, RF, and hardware tooling. Blog: travisgoodspeed.blogspot.com (since ~2008). Collaborates with Dartmouth security group (Sergey Bratus, Ryan Speers, Rebecca Shapiro) on protocol-layer research. Created the GoodFET and Facedancer tool families, foundational hardware hacking infrastructure used worldwide. Author of *Microcontroller Exploits* (No Starch Press, 2024, 408 pages).

**Tools**:
- **GoodFET**: open-source JTAG/SPI/I2C/UART/RF bus adapter based on TI MSP430. Supports JTAG debugging and programming across MSP430, Nordic nRF24L01, Chipcon CC1110/CC2430/CC2530, AVR, PIC. Protocol clients in Python. Enables firmware dumping, code protection bypass, flash read/write, debug register manipulation. Sold through Adafruit (v4.2). GitHub: github.com/travisgoodspeed/goodfet.
- **Facedancer**: USB host protocol research platform enabling USB device emulation and fuzzing from Python. Architecture: Facedancer10/20 → 21 (GoodFET41 + MAX3421E) → modern GreatFET-based (github.com/greatscottgadgets/facedancer). MSP430/microcontroller firmware kept intentionally minimal; all complexity in Python library. High-level API: define USB descriptors, handle control/bulk/interrupt endpoint transactions, implement any device class. Used to discover USB host/device trust assumptions, implement BadUSB-class attacks, perform USB MITM, fuzz USB class drivers. USBFuzz (USENIX Security 2020) found 26 bugs across Linux/macOS/Windows/FreeBSD using emulated USB devices.
- **maskromtool**: Qt6/C++ tool for extracting bits from mask ROM die photographs. Annotates optical microscope photos to identify bit cells, extracts raw bit array, assists byte ordering via correctness-grading disassembler. Tutorial for Game Boy ROM extraction at github.com/travisgoodspeed/gbrom-tutorial.
- **GoodWatch**: reverse-engineered TI CC430 calculator watch with custom firmware; demonstrates full commercial watch firmware RE and reconstruction.

**Key publication**: "Packets in Packets: Orson Welles' In-Band Signaling Attacks for Modern Radios" (USENIX WOOT 2011, with Sergey Bratus, Ricky Melgares, Rebecca Shapiro, Ryan Speers) — see Section V for full technical details.

**Talk list** (selected):
| Year | Conference | Title |
|------|------------|-------|
| 2023 | REcon / ShmooCon | Recent Experiments with Mask ROMs / A Mask ROM Tool in Qt6 and C++ |
| 2018 | REcon / ShmooCon | Building a GoodWatch (CC430 calculator watch RE) |
| 2012 | REcon | Facedancer USB: Exploiting the Magic School Bus |
| 2011 | USENIX WOOT | Packets in Packets (PiP) |
| 2009 | DEF CON 17 | An Open JTAG Debugger; Locally Exploiting Wireless Sensors |
| 2008 | DEF CON 16 | Journey to the center of the HP28 |

---

### Joe Grand ("Kingpin")

**Career arc**: Founding member of **L0pht Heavy Industries** (Boston, 1992–2000) — early hackerspace/research collective; members included Mudge (Peiter Zatko), Space Rogue, Weld Pond (Chris Wysopal). On May 19, 1998, all seven L0pht members testified before the Senate Governmental Affairs Committee, stating they could take down the Internet in 30 minutes. L0pht produced L0phtCrack (Windows NT password cracker) and pioneered responsible disclosure. L0pht merged with @stake in 2000. Grand founded **Grand Idea Studio** (Portland, OR) as independent hardware engineering and research firm. Appeared on Discovery Channel's *Prototype This!* (2008). Designed official DEF CON badge DC14–DC18 (5 consecutive years), DC China 1.0, and DC27.

**Tools**:
- **JTAGulator**: open-source JTAG/SWD/UART pinout discovery tool. First presented at DEF CON 21 and Black Hat USA 2013. Based on Parallax Propeller microcontroller. 24 I/O channels (CH0–CH23) with adjustable target I/O voltage (1.4V–3.3V); overcurrent/ESD/reverse-polarity protection. JTAG brute-force: all channel permutations as TDI/TDO/TCK/TMS/TRST; sends BYPASS instruction, looks for loopback response. SWD brute-force: SWDIO/SWDCLK permutations. UART auto-detect: injects known patterns, measures pulse widths at common baud rates. GitHub: github.com/grandideastudio/jtagulator.
- **BSODomizer HD**: FPGA-based device injecting fake BSOD onto HDMI video signals (DC24 2016).
- **OpticSpy**: open-source optical data transmission capture and analysis (DC26 2018).

**Notable research**: RoboForm Password Regeneration (DEF CON 32, 2024, with Bruno Krauss) — see Section VII for full technical walkthrough.

**Talk list** (selected):
| Year | Conference | Title |
|------|------------|-------|
| 2024 | DEF CON 32 | Joe and Bruno's Guide to Hacking Time: Regenerating Passwords from RoboForm |
| 2019 | DEF CON 27 | Behind the Scenes of the DEF CON 27 Badge |
| 2018 | DEF CON 26 | The L0pht Testimony, 20 Years Later |
| 2016 | DEF CON 24 | 101 Ways to Brick your Hardware; BSODomizer HD |
| 2014 | DEF CON 22 / Black Hat Asia | PCB RE Techniques; JTAGulator |
| 2013 | DEF CON 21 / Black Hat USA | JTAGulator: Assisted Discovery Of On-Chip Debug Interfaces |
| 2004 | DEF CON 12 | Advanced Hardware Hacking: Designs and Attacks of Secure Hardware |
| 1997 | Beyond HOPE | The L0pht |

---

### Supporting Researchers

**Trammell Hudson** (Two Sigma): Thunderstrike (31C3 Dec 2014) — first public EFI bootkit for Apple MacBooks via Thunderbolt Option ROM; Thunderstrike 2 (BH/DC23 2015, with Kovah/Kallenberg) — first firmware worm for Macs, eliminated hardware access requirement via "Darth Venamis" software-exploitable SPI flash write path. Creator of Heads firmware (coreboot + Linux-based, TPM-measured boot, hardware root of trust for ThinkPads). See Section IV for full Thunderstrike technical chain.

**Xeno Kovah and Corey Kallenberg** (LegbaCore, then Apple Platform Security): systematic UEFI vulnerability disclosure affecting Dell, HP, Lenovo (2013–2015). "How Many Million BIOSes Would You Like to Infect?" (CanSecWest 2015) — LightEater implant using undocumented SMI handlers for SMM-level execution + SPI flash reflash. Thunderstrike 2 collaboration. Both hired by Apple to work on platform security (2015). Kallenberg won 2015 Pwnie Award for Best Privilege Escalation (UEFI Capsule Update interface memory corruption).

**Yuriy Bulygin and Mickey Shkatov** (Intel ATR → Eclypsium): created CHIPSEC (github.com/chipsec/chipsec) — open-source platform security assessment framework for Intel x86/x64. Runs on Windows, Linux, UEFI Shell, macOS. Provides security test suite (known UEFI/BIOS misconfigurations), low-level hardware access tools (direct SPI flash access, MSR read/write, PCI config, SMRAM examination), and forensic modules (UEFI firmware parser, rootkit detection). Bulygin founded Eclypsium (supply chain firmware security company).

**Alex Matrosov and the Binarly REsearch team** (Binarly, founded 2021): assumed the heir-apparent position for systematic IBV / UEFI vulnerability disclosure after the LegbaCore / Eclypsium founding era. Binarly maintains a public advisory series (`BRLY-YYYY-NNN`). 2023–2025 disclosure flagship was LogoFAIL (BRLY-2023-006, see §IV) — 29 image-parser bugs across AMI, Insyde, Phoenix yielding 15 exploitable CVEs (CVE-2023-40238, CVE-2023-5058, CVE-2023-39538, CVE-2023-39539). 2024 disclosure flagship was PKfail (BRLY-2024-005, VU#455367) — see §IV. Matrosov authored *Rootkits and Bootkits: Reversing Modern Malware and Next Generation Threats* (No Starch, 2019) with Eugene Rodionov and Sergey Bratus. Binarly also publishes the free `efiXplorer` IDA plugin (github.com/binarly-io/efiXplorer) for UEFI DXE / SMM module RE — the canonical successor to UEFITool-only workflows for analysts. Sources: [Binarly LogoFAIL advisory](https://www.binarly.io/advisories/brly-2023-006), [Binarly PKfail blog](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem), [CERT/CC VU#455367](https://kb.cert.org/vuls/id/455367).

**ESET firmware research group** (Aryeh Goretsky, Martin Smolár, et al.): in-the-wild UEFI threat discovery + IOC publication for the post-LoJax era. Notable disclosures: BlackLotus public confirmation (March 2023, [welivesecurity blog](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)); Bootkitty (November 2024, [welivesecurity](https://www.welivesecurity.com/en/eset-research/bootkitty-analyzing-first-uefi-bootkit-linux/)) — first UEFI bootkit for Linux (BoB student PoC, but production-shaped); HybridPetya (September 2025, [welivesecurity](https://www.welivesecurity.com/en/eset-research/introducing-hybridpetya-petya-notpetya-copycat-uefi-secure-boot-bypass/)) — Petya/NotPetya copycat with CVE-2024-7344 Secure Boot bypass. ESET also discovered CVE-2024-7344 itself (`reloader.efi` Microsoft-signed bootloader loading `cloak.dat` payload without integrity check), disclosed January 2025; Microsoft `dbx` revocation followed. See §IV "UEFI Rootkit Taxonomy" extensions below.

---

## II. Firmware Acquisition Techniques

### JTAG / SWD Extraction

**IEEE 1149.1 JTAG** — 4-wire (+optional TRST) interface: TCK (clock), TDI (data in — shifts into target), TDO (data out — shifts from target), TMS (mode select — drives TAP state machine), TRST (reset, active-low, optional).

**TAP state machine** — 16-state FSM. Key states: Test-Logic-Reset (entry; TMS=1 for 5+ TCK cycles from any state), Run-Test/Idle (idle), Shift-DR/Shift-IR (active scan states). State transitions are TMS-value-driven on rising TCK edge.

**Mandatory instructions**: BYPASS (all 1s) — 1-bit passthrough register; IDCODE (optional) — 32-bit device identifier (Bit 0 = 1, bits 1–11 = manufacturer ID, bits 12–27 = part number, bits 28–31 = version); EXTEST — connects boundary scan cells; SAMPLE/PRELOAD — snapshot I/O state.

**Full memory read via JTAG (ARM CoreSight)**: attach via SWD or JTAG, enable debug via DHCSR register write, use MEM-AP (Memory Access Port) to read arbitrary physical addresses including Flash/SRAM. OpenOCD command: `flash read_bank 0 firmware.bin 0 0x100000`.

**ARM SWD (Serial Wire Debug)**: two-wire replacement for JTAG (SWDIO bidirectional, SWDCLK). Same memory access capability as JTAG CoreSight. Switch from JTAG via specific bit pattern on TMS/SWDIO.

**ARM CoreSight Debug Authentication**: controlled by DBGEN (invasive debug enable), SPNIDEN, SPIDEN, NIDEN signals — typically driven by eFUSE values or TrustZone Secure World policy. Bypass approaches: EMFI to disrupt auth check (Ang Cui), fault injection during boot before auth is enforced (Goodspeed), logic-level glitching.

**Toolchain**: JTAGulator (pinout discovery) → OpenOCD (protocol execution, memory access) → GDB (interactive debugging).

### SPI Flash Extraction

**Protocol basics**: 4 signals — MOSI, MISO, SCK, CS# (active-low). SPI Mode 0 (CPOL=0, CPHA=0) is most common. Frame: CS# low → byte command (MSB first) → 3-byte address → data → CS# high.

**Common flash chips**: Winbond W25Q series (W25Q32–W25Q256, 32–256Mbit, SOIC-8/WSON-8), Macronix MX25L series, ISSI IS25LP series, Microchip SST26.

**In-circuit extraction procedure**:
1. Identify SOIC-8 or WSON-8 chip near SoC (silkscreen U8, U9, "FLASH")
2. Attach SPI clip (Pomona 5250) to chip while powered off
3. Power board; if SoC drives SPI during operation, hold SoC in reset while reading
4. `flashrom -p ft2232_spi:type=2232H,port=B,divisor=4 -r firmware.bin`
5. Verify: `flashrom -p ft2232_spi:type=2232H,port=B -v -f firmware.bin`

Other programmers: FT232H breakout, Bus Pirate (slow — ~30 min for 8MB), Raspberry Pi SPI GPIO, SPIDriver.

### UART Console Access

Most embedded Linux devices expose U-Boot or kernel console on UART (3.3V logic):
1. Identify TX, RX, GND pads — often J1, DEBUG, CON1; look for 3-4 pin header near SoC
2. JTAGulator UART scan or logic analyzer capture to identify baud rate; common: 115200, 57600, 38400, 9600
3. Connect CP2102/FT232RL adapter (3.3V — NOT 5V): `screen /dev/ttyUSB0 115200`
4. Interrupt U-Boot during 3-second countdown
5. U-Boot shell: `printenv`, `run bootcmd`, `md 0x20000000 0x100` (memory dump hex)
6. Bypass init: `setenv bootargs "${bootargs} init=/bin/sh"` → drops to root shell

### Power Glitching

Briefly (~100ns–10µs) dropping or spiking VCC disrupts internal voltage regulators, causing transient logic errors — CPUs execute incorrect instructions, skip checks, or read corrupted values.

**ChipWhisperer** (NewAE Technology): open-hardware glitching platform with sub-nanosecond pulse timing via FPGA. Includes power analysis (side-channel) and glitching in one board.

**ChipWhisperer-Husky / Husky-Plus (2023–2025)**: compact successor; integrates power analysis, voltage glitching, and clock glitching with sequenced triggers (specify a sequence of events that must occur in order before pulse fires — eliminates a class of "trigger fires too early" failure modes that plagued the original Lite). High-speed logic analyzer integrated for glitch visualization. Real-time data streaming for asymmetric-algorithm power analysis. Open-source (FPGA logic, MCU firmware, host code). Husky-Plus extends with a larger FPGA (Artix-7 A100T), a 250 MS/s ADC, larger sample buffers, and up to 4 sequenced triggers. See [Husky / Husky-Plus manual May 2025](https://media.newae.com/manuals/cwhusky_cwhuskyplus_manual_may2025.pdf), [Crowd Supply page](https://www.crowdsupply.com/newae/chipwhisperer-husky). Cross-link [hardware_side_channels_expertise.md](hardware_side_channels_expertise.md) for the power-analysis side of the same toolchain.

**STM32 RDP bypass** (Read Protection):
- RDP 0 = unprotected; RDP 1 = no JTAG flash read; RDP 2 = permanent lock (irreversible); regression from RDP 1 to RDP 0 triggers flash mass erase
- `openocd -f interface/stlink.cfg -f target/stm32f1x.cfg` → `flash read_bank 0 dump.bin 0 0x20000`

**Trezor One (2020)**: STM32F205 fault injection. Kraken Security Labs demonstrated a first voltage glitch re-enabling the STM32's integrated bootloader → second glitch allows reading flash 256 bytes at a time → full flash dump → encrypted seed + PIN brute-force.

### EMFI (Electromagnetic Fault Injection)

Focused coil placed near target PCB induces localized eddy currents. No galvanic connection required — works through PCB substrate, conformal coating, potting compound. Effective spatial resolution ≈ coil diameter.

**BADFET (Ang Cui / Rick Housley, WOOT 2017)**: second-order EMFI — rather than directly targeting the CPU, pulses are directed at peripheral conductors (power delivery network traces, clock distribution, memory bus). These induced currents propagate to CPU via board interconnects. Key advantage: shielding the CPU doesn't protect the power traces. Demonstrated defeating ARM TrustZone secure boot on Cisco 8861 IP Phone (Broadcom BCM11123 SoC). Platform: badFET board with sub-microsecond pulse timing; software trigger synchronizes pulses with execution of the secure boot signature check.

### Chip Decapping and Physical Analysis

**Acid decapsulation**: fuming nitric acid (>90% HNO3) dissolves epoxy mold compound without attacking silicon die or metal interconnects. Process: chip on hotplate at ~100°C, apply fuming HNO3 dropwise, rinse with acetone + IPA.

**Post-decap analysis**:
- Optical microscope: visual inspection, mask ROM bit reading
- SEM (Scanning Electron Microscope): sub-micron feature analysis
- FIB (Focused Ion Beam): cut metal interconnects, deposit new traces, expose buried layers — used to bypass security fuses, create test points on inaccessible internal nodes

**maskromtool workflow**: photograph die under optical microscope → import in maskromtool → annotate bit cells at row/column intersections → export raw bit array → grading disassembler helps determine logical byte ordering.

---

## III. Firmware Analysis and Emulation

### Identification and Unpacking

**binwalk** (github.com/ReFirmLabs/binwalk, creator Craig Heffner):
- Scans firmware binary for magic bytes at every offset; reports file type, offset, description
- Entropy analysis: high entropy (>0.9) = likely compressed or encrypted
- Recursive extraction: `binwalk -eM firmware.bin` → `_firmware.bin.extracted/` directory tree
- Recognizes: squashfs, cramfs, JFFS2, YAFFS2, ext2, gzip, LZMA, XZ, ZIP, CPIO, UBI, FIT, Linux kernel zImage/uImage, ELF, PE, Mach-O, U-Boot headers, UEFI capsule

**File system tools**:
- squashfs: `unsquashfs -dest extracted/ filesystem.squashfs`
- JFFS2: `jefferson -d extracted/ filesystem.jffs2`
- YAFFS2: `unyaffs filesystem.yaffs2 extracted/`
- UBI/UBIFS: `ubireader_extract_images firmware.ubi`

**OFRAK workflow**:
1. `ofrak.run()` → instantiate analysis pipeline
2. `unpack()` → recursive unpack via registered unpackers per container type
3. Navigate resource tree: parent → children → identify interesting leaves (ELF executables, scripts, config files)
4. Analyze: angr (control flow), Ghidra (disassembly), string extraction, entropy
5. Patch: `Modifier` components overwrite bytes, add/remove resources, modify ELF sections
6. Repack: recursively repack from leaves to root, preserving format, checksums, compression

**FACT (Firmware Analysis and Comparison Tool)**: web-based framework for automated unpacking, analysis, comparison, CVE matching. Plugin-based; includes unpacking (wraps binwalk), hardcoded credential detection, crypto key scanning, known-vuln matching.

### Static Analysis

**Toolchain**: Ghidra (NSA, free, 200+ ISAs) / IDA Pro (industry standard) / Binary Ninja / radare2.

**Ghidra SVD-Loader**: for Cortex-M firmware, import CMSIS SVD XML for target chip. SVD defines all peripheral register addresses and bitfields; SVD-Loader applies these as struct overlays, turning `0x40013800` into `USART1->SR` with named bits. Dramatically accelerates peripheral interaction analysis.

**Finding credentials**:
```
strings firmware.bin | grep -iE "password|passwd|admin|root|secret"
grep -r "password" extracted_rootfs/etc/
find extracted_rootfs/ -name "*.conf" -exec grep -l "password" {} \;
```
Private keys: look for `-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN EC PRIVATE KEY-----`.

**Hardcoded credential pattern**: `strcmp(input, "admin")` in authentication handlers — automated via FACT credential plugin, firmwalker.

**Buffer overflows**: trace data flow from `recv()`/HTTP body → `strcpy()`/`sprintf()` → stack buffer. Common in CGI handlers: `strcpy(buf, query_param)` without length check.

**Format string bugs**: `printf(user_input)`, `sprintf(buf, format_str_from_network)` in HTTP CGI handlers, SNMP handlers, UPNP description parsing.

### Firmware Emulation

**QEMU + chroot** (Linux-based firmware):
```
qemu-arm-static -L /path/to/extracted/rootfs /path/to/extracted/rootfs/bin/sh
```
Works well for Cortex-A Linux firmware; fails with proprietary hardware peripherals.

**Firmadyne** (github.com/firmadyne/firmadyne): automated pipeline — web scraper collects firmware from manufacturer sites → binwalk extraction → QEMU kernel + rootfs emulation → automated vulnerability scanning (60 known CVEs + 14 novel CVEs found). Evaluated on 23,035 images; 9,486 extracted; 887 vulnerable to ≥1 of the 74 sampled exploits. Emulation success rate: ~16%. **FirmAE** achieves ~79% via five arbitration techniques.

**Avatar2** (github.com/avatartwo/avatar2, Eurecom): hardware-in-the-loop — firmware runs in QEMU while I/O accesses forwarded to real hardware via OpenOCD. Enables: peripheral forwarding, execution recording and replay (PANDA integration), selective instrumentation via angr.

### Common Firmware Stacks

| Stack | Use Case | Notes |
|-------|----------|-------|
| OpenWRT (Linux + BusyBox + uClibc/musl) | Home routers | SSH/Telnet/LuCI; most consumer router firmware |
| VxWorks (Wind River, commercial RTOS) | Industrial, avionics | Proprietary format; Ghidra VxWorks loader |
| ThreadX / Azure RTOS | IoT controllers | Extremely small footprint (~2KB ROM / 1KB RAM min) |
| FreeRTOS | Cortex-M devices | Cooperative or preemptive; heap_1 through heap_5 |
| Bare-metal Cortex-M | Microcontroller products | Interrupt vector table at 0x0; CMSIS SVD for peripheral map |
| U-Boot | Embedded Linux bootloader | Initializes DRAM, SPI flash, MMC; interactive shell |

---

## IV. Secure Boot and Trust Chain Attacks

### UEFI Architecture

**Boot phases**:
1. **SEC**: first code after power-on; initializes processor cache-as-RAM (CAR); establishes root of trust
2. **PEI**: memory controller init, DRAM training; PEIMs loaded
3. **DXE**: main UEFI environment; DXE drivers loaded; EFI_BOOT_SERVICES and EFI_RUNTIME_SERVICES established
4. **BDS**: enumerates boot options, launches boot manager
5. **TSL**: OS loader runs; calls ExitBootServices() to transition to OS

**Secure Boot key hierarchy**:
- **PK (Platform Key)**: single root of trust; factory-set; enrolling new PK requires physical presence or firmware consent
- **KEK (Key Exchange Keys)**: signed by PK; allow updating db/dbx
- **db (signature database)**: hashes and certificates of allowed EFI binaries
- **dbx (forbidden signature database)**: revocation list of known-bad binaries

OS loader (bootmgfw.efi or shim.efi) measured against db/dbx; if signature in db and not in dbx → execution proceeds.

**Intel Boot Guard** (separate from Secure Boot): hardware-rooted measured boot using ACM (Authenticated Code Module) executed from protected ROM. Cannot be disabled by software once eFUSEs blown. Measures IBB (Initial Boot Block = PEI phase) against manifest in flash. If enabled and IBB is modified, system will not boot.

### UEFI Rootkit Taxonomy

**LoJax (2018)** — first in-the-wild UEFI rootkit. Threat actor: Sednit/APT28/Fancy Bear (Russian GRU).
1. Deploy user-mode tools to read SPI flash (RWEverything driver — legitimate UEFI utility)
2. Inject custom UEFI DXE driver into SPI flash firmware image
3. Reflash SPI flash using RWEverything with modified image
4. Modified DXE driver runs at each boot, drops user-mode implant to disk, ensures execution after OS boots
5. Survives OS reinstall and hard drive replacement
Code basis: its NTFS DXE driver is Hacking Team's NtfsDxe from the leaked vector-edk project (2015). Targets: government organizations in Balkans, Central and Eastern Europe.

**MosaicRegressor (2020)** — Chinese-speaking actor, Winnti connections. Same SPI flash injection technique as LoJax; also VectorEDK-based. Multi-stage framework targeting diplomats and NGO members (2017–2019).

**CosmicStrand (2022)** — Chinese-speaking actor. Discovery: Kaspersky July 2022; active since end of 2016 (years before UEFI rootkits were publicly discussed). Hooks CSMCORE DXE driver → installs kernel-mode hook → connects to C2, downloads Windows kernel-mode payload each reboot. Targets private individuals in China, Vietnam, Iran, Russia.

**BlackLotus (2023)** — crimeware kit. CVE: CVE-2022-21894 ("Baton Drop").
1. Uses legitimately signed but vulnerable `bootmgfw.efi`/`hvloader.efi` from before January 2022 patch
2. Exploits CVE-2022-21894 to enroll attacker's Machine Owner Key (MOK)
3. Attacker's self-signed bootkit accepted by Secure Boot
4. Disables HVCI, BitLocker, and Windows Defender
Key insight: fully-patched Windows 11 was vulnerable because revocation list (dbx) had not been updated to include vulnerable binaries. Microsoft subsequently issued dbx updates.

**Thunderstrike (Trammell Hudson, 31C3 December 2014)**:
1. Thunderbolt Option ROMs loaded and executed during EFI initialization, before OS
2. Apple's EFI firmware trusted Thunderbolt Option ROM without cryptographic validation
3. Attacker writes malicious Option ROM to Thunderbolt peripheral (~5 min physical access)
4. On boot, Option ROM code executes in EFI context with full EFI services access
5. Overwrites SPI flash; replaces Apple's RSA public key with attacker's key
6. Bootkit propagates by writing itself to new Thunderbolt devices' Option ROMs — air gap traversal via shared peripherals

**Thunderstrike 2 (Hudson + Kovah + Kallenberg, BH/DC23 2015)**:
- Eliminated hardware access requirement via "Darth Venamis" (software path from root → SPI flash write)
- Used four previously-disclosed UEFI vulnerabilities plus unsigned Option ROM acceptance
- First firmware worm for Macs; persists through S3 resume; hides in SMM; can brick systems by corrupting NVRAM

**Bootkitty (ESET, November 2024)** — first UEFI bootkit targeting Linux. PoC origin (Korea's Best of the Best training program), but production-shaped. Hooks UEFI authentication protocols to bypass Secure Boot; hooks GRUB functions to disable kernel integrity checks; preloads two ELF binaries via the Linux init process. Limitation: uses hardcoded byte patterns to locate target functions, restricting kernel/GRUB version coverage. Significance: refutes the long-standing "UEFI bootkits are a Windows-only problem" assumption. ESET also discovered a possibly related unsigned kernel module (`BCDropper`). Sources: [welivesecurity](https://www.welivesecurity.com/en/eset-research/bootkitty-analyzing-first-uefi-bootkit-linux/), [bleepingcomputer](https://www.bleepingcomputer.com/news/security/researchers-discover-bootkitty-first-uefi-bootkit-malware-for-linux/).

**HybridPetya (ESET, September 2025)** — fourth publicly-known UEFI bootkit family with Secure Boot bypass, joining BlackLotus / Bootkitty / a Hyper-V Backdoor PoC. Weaponizes **CVE-2024-7344** (disclosed by ESET January 2025): the Microsoft-signed `reloader.efi` shim loads an embedded UEFI application from `cloak.dat` "in a very unsafe way, completely ignoring any integrity checks." Bootkit install path: writes malicious `bootmgfw.efi` replacement to `\EFI\Microsoft\Boot\`, backs up the legitimate loader to `bootmgfw.efi.old`, drops `config`/`verify`/`counter` files alongside; deletes fallback `\EFI\Boot\Bootx64.efi`. Encrypts the NTFS Master File Table with Salsa20 (Petya/NotPetya genealogy), displays a fake CHKDSK message during the encrypt pass. No in-the-wild use as of disclosure; samples uploaded to VirusTotal from Poland February 2025. Microsoft `dbx` update revoking the `reloader.efi` signature shipped with the January 2025 Patch Tuesday. Source: [welivesecurity HybridPetya analysis](https://www.welivesecurity.com/en/eset-research/introducing-hybridpetya-petya-notpetya-copycat-uefi-secure-boot-bypass/).

**Post-BlackLotus revocation timeline (CVE-2023-24932)**: Microsoft elected a structural fix rather than a binary-by-binary `dbx` extension. Mitigations shipped in tranches with explicit deployment phases: initial deployment May 9, 2023 → second deployment July 11, 2023 → evaluation phase April 9, 2024 (Windows UEFI CA 2023 added to `db`; "Windows Production PCA 2011" `dbx` revocation available manually) → deployment phase July 9, 2024 → enforcement phase (automatic PCA 2011 `dbx` revocation) not before January 2026. The 2011 PCA still signs current Windows boot binaries, so revoking it requires every supported OEM firmware to first enroll the 2023 certs. Sources: [Microsoft KB on CVE-2023-24932](https://support.microsoft.com/en-us/topic/41a975df-beb2-40c1-99a3-b3ff139f832d), [Windows IT Pro blog](https://techcommunity.microsoft.com/blog/windows-itpro-blog/revoking-vulnerable-windows-boot-managers/4121735).

### LogoFAIL (BRLY-2023-006, disclosed January 2024) — Detailed Analysis

**Researchers**: Binarly REsearch team (Alex Matrosov et al.). Public disclosure December 6, 2023 at Black Hat Europe.

**Root cause**: the BIOS/UEFI boot-time logo splash screen ("Press F2 for setup...") is rendered by an in-firmware image parser running in DXE phase, well before any OS or Secure Boot exit. Each IBV (Independent BIOS Vendor) ships its own image decoder for BMP/GIF/JPEG/PCX/PNG/TGA — decades-old C parsers carried into modern UEFI without modern memory safety. Binarly found 29 distinct issues across the three major IBVs; 15 yielded arbitrary code execution.

**CVE assignments** (4 of 29 issues received CVEs):
- **CVE-2023-40238** (Insyde): multi-format decoder issues
- **CVE-2023-5058** (Phoenix): `SystemImageDecoderDxe` module
- **CVE-2023-39538, CVE-2023-39539** (AMI): `AMITSE` driver
- CVSS 8.2 High

**Exploitation chain**:
1. Attacker with write access to the EFI System Partition (ESP) — i.e. root or Administrator on the running OS — writes a maliciously crafted logo image to the firmware's logo storage location (an NVRAM variable on some platforms, an ESP path on others; varies by IBV).
2. On the next boot, the DXE image parser parses the crafted image and the parsing bug yields arbitrary code execution in firmware context (ring -2 / DXE) **before** Secure Boot exits to the OS loader.
3. Implant survives OS reinstall, persists across drive replacement, and runs before any OS-level EDR can observe it.

**Affected scope**: hundreds of consumer + enterprise device models across Acer, Dell, Framework, Fujitsu, Gigabyte, HP, Intel, Lenovo, MSI, Samsung, Supermicro. Both x86 and ARM UEFI implementations affected. Binarly's BRLY-2023-006 advisory enumerated explicit Lenovo product-line coverage (Yoga, ThinkBook, Legion, IdeaPad, ThinkCentre, ThinkStation).

**Architectural significance**: LogoFAIL crosses two trust boundaries that were widely assumed to be safely isolated — (a) the assumption that NVRAM / ESP-stored "preferences" are inert data not parsed by privileged code, and (b) the assumption that Secure Boot bounds the trust surface for OS-resident attackers. Neither held. This is the canonical 2023–2024 reference for "the firmware attack surface includes everything it parses, including the logo." Sources: [Binarly BRLY-2023-006](https://www.binarly.io/advisories/brly-2023-006), [Hacker News writeup](https://thehackernews.com/2023/12/logofail-uefi-vulnerabilities-expose.html), [Bleeping Computer](https://www.bleepingcomputer.com/news/security/logofail-attack-can-install-uefi-bootkits-through-bootup-logos/).

### PKfail (BRLY-2024-005, disclosed July 25 2024) — Detailed Analysis

**Researchers**: Binarly REsearch team. Public disclosure July 25, 2024; follow-on findings presented at LABScon September 2024. CERT/CC tracking: **VU#455367**. Subsequent CVE: **CVE-2024-8105**.

**Root cause**: the **Platform Key (PK)** is the single root of trust for UEFI Secure Boot — only PK-signed updates can modify KEK / db / dbx. American Megatrends International (AMI) shipped a test PK in its UEFI reference implementation marked with subject/issuer strings containing `DO NOT TRUST` or `DO NOT SHIP`, with the explicit expectation that downstream OEMs would replace it with a per-device production key. Instead, hundreds of device models shipped to production with the test PK intact — across 22 distinct untrusted keys in Binarly's enumeration. Because the test PK private key is recoverable (leaked on a public GitHub repository through a data leak at an ODM), an attacker holding it can sign arbitrary KEK / db / dbx updates and silently enroll attacker-controlled signers as trusted by Secure Boot.

**Affected scope**: over 800 device models from Lenovo, Dell, HP, HPE, Supermicro, Intel, MSI, Gigabyte, and Acer; Binarly scan data shows >10% of all surveyed firmware images carry an untrusted PK. **First vulnerable firmware**: 2012. **Most recent vulnerable firmware at disclosure**: June 2024 — a 12-year span making PKfail one of the longest-lived supply-chain failures publicly documented in the platform-security space.

**Detection**: search the platform's enrolled PK certificate subject/issuer for the literal strings `DO NOT TRUST` or `DO NOT SHIP`. Binarly published the `BRLY-2024-005` advisory with the full untrusted-key fingerprint list; firmware analysts use `chipsec_util uefi var-list | grep -i 'do not'` (CHIPSEC) or `efivar -l | xargs -I{} efivar -p -n {}` (efivar) for runtime detection.

**Remediation**: cannot be fixed by software-only update — the PK must be re-keyed, which requires OEM firmware action (`SetVariable` to install a fresh, OEM-controlled PK signed by the new private key chain). For deployed fleets, mitigation is firmware-update-or-replace. Sources: [Binarly PKfail blog](https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem), [CERT/CC VU#455367](https://kb.cert.org/vuls/id/455367), [Binarly research PDF](https://22222483.fs1.hubspotusercontent-na1.net/hubfs/22222483/Reports/PKfail%20-%20Binarly%20Research%20Report%20July%2025%202024.pdf), [BleepingComputer follow-up](https://www.bleepingcomputer.com/news/security/pkfail-secure-boot-bypass-remains-a-significant-risk-two-months-later/).

### Thrangrycat (CVE-2019-1649) — Detailed Analysis

**Researchers**: Ang Cui, Jatin Kataria, Rick Housley (Red Balloon Security). Disclosed May 2019. DEF CON 27 / Black Hat USA 2019.

**Background**: Cisco Trust Anchor module (TAm) is embedded in virtually all Cisco routing/switching hardware: ASR/ISR/CSR routers, ASA/Firepower firewalls, Catalyst/Nexus/NCS switches, 100+ product families. Implemented as a small FPGA (Xilinx Spartan class) that validates Cisco IOS/IOS XE cryptographic signature before allowing OS boot.

**The vulnerability**:
1. FPGA bitstream stored in SPI flash **unencrypted and unprotected**
2. Attacker with root-level access identifies the TAm SPI flash chip
3. FPGA bitstream can be modified to disable or alter trust verification logic
4. Red Balloon released BAL (Binary Abstraction Layer) + BAL-Xilinx tooling for Xilinx bitstream packing/unpacking, device detection, encryption detection, and **pin modification** (forcing TAm I/O pins high or low, disabling trust anchor output)
5. Writing modified bitstream to TAm SPI flash is persistent across reboots; can lock out future software updates to itself

**Exploit chain**: CVE-2019-1649 (local root required) + CVE-2019-1862 (Cisco IOS XE Web UI command injection, exploitable by an authenticated administrator) = remote, persistent compromise of hardware trust anchor from the internet.

**Remediation**: Cisco patched to restrict TAm SPI flash access via firmware guards. Red Balloon assessed this is a **fundamental hardware design flaw** — full remediation may require hardware replacement.

### CHIPSEC Technical Reference

```bash
sudo python chipsec_main.py                              # Full audit
sudo python chipsec_main.py -m common.smrr               # SMRR configuration
sudo python chipsec_main.py -m common.bios_wp             # BIOS write protection (BIOS_CNTL)
sudo python chipsec_main.py -m common.secureboot.variables # Secure Boot variable protection
sudo python chipsec_main.py -m tools.uefi.scan_image      # Scan for known vuln patterns
sudo python chipsec_util.py spi dump spi.bin              # Dump SPI flash
sudo python chipsec_util.py uefi var-list                 # Read UEFI variables
```

**Critical checks**:
- `BIOS_CNTL` register (PCI 0:31:0, offset 0xDC): bit 0 = BIOSWE (BIOS Write Enable, must be 0); bit 1 = BLE (BIOS Lock Enable, must be 1). If BLE=0 or BIOSWE=1, OS can write SPI flash.
- SMRR (IA32_SMRR_PHYSBASE / IA32_SMRR_PHYSMASK MSRs): must define SMRAM range; prevents cache-based SMRAM attacks
- TSEGMB / BGSM PCI registers: define SMRAM base and top; lock bit must be 1 before OS boots

### Embedded Linux Verified Boot

**U-Boot FIT image chain**:
- FIT (Flattened uImage Tree): single binary with kernel + DTB + optional initrd in signed FDT container
- RSA signing: `mkimage -f image.its image.fit` with private key; algorithm: "sha256,rsa2048" or "sha512,ecdsa256"
- U-Boot builds corresponding public key into its own FDT (CONFIG_OF_CONTROL)
- Full chain: hardware ROM with burned public key hash → signed U-Boot → signed FIT (kernel + DTB) → dm-verity root hash in kernel cmdline → signed root filesystem

**dm-verity**: block device integrity via Merkle tree over filesystem blocks; root hash verified against trusted value at boot time. Used by Android Verified Boot, ChromeOS.

---

## IV.5 Hardware Security Elements (TPM, Pluton, Titan, Secure Enclave) — 2024–2026 currency

### TPM 2.0 Reference Implementation Vulnerabilities

The TCG TPM 2.0 reference library implementation (`MS_TPM_20_REF`, github.com/microsoft/ms-tpm-20-ref) is the canonical source code for both hardware TPM vendors (Infineon, Nuvoton, ST) and firmware TPM (fTPM) implementations (AMD `fTPM` in PSP, Intel `PTT` in CSME, Microsoft Pluton). A vulnerability in the reference flows downstream to every implementation that didn't independently patch.

**CVE-2023-1017, CVE-2023-1018 (Quarkslab, February 2023)** — first wave: out-of-bounds read/write in `CryptParameterDecryption`. Affected: implementations following revision 1.59 of the TPM 2.0 spec. AMD published bulletin AMD-SB-7002; Infineon stated it was not affected. Source: [Quarkslab blog](https://blog.quarkslab.com/vulnerabilities-in-the-tpm-20-reference-implementation-code.html), [VU#782720](https://kb.cert.org/vuls/id/782720).

**CVE-2025-2884 (TCG VRT0009 advisory, June 2025)** — second wave: out-of-bounds read in `CryptHmacSign`. CVSS 6.6 Medium. The reference code does not consistency-check signature scheme parameters before HMAC computation, yielding OOB reads from the TPM's command buffer. Practical impact: attacker with TPM command-interface access (any local process with NTPM / `/dev/tpm0`) can read potentially-sensitive memory adjacent to the command buffer or trigger DoS. Affects AMD fTPM. TCG published an errata to the TPM 2.0 Library Specification (revision 01.83, March 2024) and updated the reference implementation. Sources: [VU#282450](https://www.kb.cert.org/vuls/id/282450), [TCG VRT0009 advisory PDF](https://trustedcomputinggroup.org/wp-content/uploads/VRT0009-Advisory-FINAL.pdf), [RHSA-2024:4408](https://access.redhat.com/errata/RHSA-2024:4408), [AMD SB-4011](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-4011.html).

**Operational note**: TPM-resident secrets (BitLocker recovery keys, SSH host keys sealed to PCRs, identity-bound credentials) are NOT directly disclosed by these bugs — the OOB reads are scoped to the reference implementation's command-processing buffers, not the persistent NV storage. The real risk is bypass of TPM-enforced sealing policies via command-flow corruption, not key extraction. Detection: monitor for `TPM2_Sign` / `TPM2_HMAC` command traffic from unexpected callers.

### Microsoft Pluton (2024 status)

Pluton — originally designed for Xbox One (2013) — shipped in mainstream PCs starting AMD Ryzen 6000 (2022), then Qualcomm SQ3 / Snapdragon-X (2024); enabled-by-default on all Copilot+ PCs from Q3 2024. Architecture: dedicated hardware security processor embedded in the larger SoC, with its own microcontroller, ROM-anchored boot, and SRAM-loaded integrity-verified firmware. Provides hardware root of trust, sealed identity, attestation, and cryptographic services; can be configured as the system TPM, replacing discrete dTPM or fTPM-on-PSP.

**Notable 2024 architectural shift**: AMD + Intel Pluton firmware foundation moved to **Rust** (presented by Bobby Reynolds and Gustavo Scotti, Microsoft, TockWorld 7, June 2024 — "Porting Tock to x86 for Pluton"). This is the canonical commercial-scale deployment of Rust in a HW security processor: Tock's capability-based isolation gives per-capsule fault containment, and the memory-safety property removes the entire C-class bug pile from the platform's primary trust boundary. Source: [Microsoft Pluton learn docs](https://learn.microsoft.com/en-us/windows/security/hardware-security/pluton/microsoft-pluton-security-processor), [Windows IT Pro Blog 2024 update](https://techcommunity.microsoft.com/blog/windows-itpro-blog/understanding-the-microsoft-pluton-security-processor/4370413). Tock + Pluton parallels Google Ti50 / OpenTitan (also Tock-based on the Chromebook GSC chip).

Cross-link: [rtos_embedded_os_expertise.md](rtos_embedded_os_expertise.md) for Tock's capsule isolation model; [hardware_side_channels_expertise.md](hardware_side_channels_expertise.md) for the side-channel surface Pluton attempts to bound; [confidential_computing_expertise.md](confidential_computing_expertise.md) for the broader hardware-root-of-trust ecosystem.

### Apple Secure Enclave Processor (SEP) and Apple Silicon — 2024–2026 research currency

**SEP architectural primer**: a separate ARMv8 core (typically a single small Apple-designed core) sharing the SoC die with the AP (Application Processor) but isolated by hardware boundary. Owns key storage, biometric template matching (Touch ID / Face ID), iCloud Keychain key material, FileVault/data-at-rest keys. Communicates with AP through a strictly-defined mailbox protocol. Boots from immutable mask ROM ("SecureROM"), then signed `sepOS` firmware. `sepOS` source is closed, but PCC software images include the `sepOS` firmware and the `iBoot` bootloader in plaintext (a first for Apple platforms — see below). The SEP is the canonical "trust anchor that survives full AP compromise" on Apple devices and is the primary blocker to checkm8-style extraction of cryptographic key material.

**PACMAN (MIT CSAIL, ISCA 2022) follow-on research**:
- **"Demystifying Pointer Authentication on Apple M1" (USENIX Security 2023, Cai Zechao et al.)**: documents the 9 distinct PAC modifier types used by XNU, the customized key-management scheme Apple layered on top of stock ARMv8.3-A PAC. Source: [USENIX paper](https://www.usenix.org/system/files/usenixsecurity23-cai-zechao.pdf).
- **Differential cryptanalysis of FEAT_PACQARMA3 (eprint 2025/321)**: reduced-round attacks on the PAC MAC function. Not directly practical on production silicon but bounds the cryptographic margin Apple retained when reducing block size. Source: [IACR ePrint 2025/321](https://eprint.iacr.org/2025/321).

**checkm8-era anchoring** (cross-reference for game-console-class BootROM bugs): the 2019 checkm8 UaF in USB DFU mode remains the canonical example of "an immutable bug in mask ROM is permanent for the entire silicon generation." A11 and earlier Apple silicon (iPhone 4S through iPhone X) — and by extension every Apple Watch, Apple TV, and iPad of that generation — are still exploitable in 2024–2026; the only "patch" is silicon replacement. Apple's response since A12 was hardware-level: SoC-resident execution boundaries via mitigations like PAC + APRR + the Secure Page Protection Controller, plus the SEP being involved earlier in the trust chain. Cross-link [game_console_security_expertise.md](game_console_security_expertise.md) for the parallel evolution in Switch / PS5 / Xbox-Series BootROM design.

**Apple Private Cloud Compute (PCC, announced WWDC 2024, security guide October 2024)** — important because it is the first time Apple has voluntarily extended its silicon-attestation chain to a server-side workload AND published the source code + binary images for security-critical components:

- **Hardware foundation**: custom server SoCs based on Apple Silicon (M-class derivatives); Secure Enclave randomizes data-volume encryption keys on every reboot and never persists them (cryptographic erasure across restarts).
- **Trust Cache**: only Apple-signed code with a trust-cache entry can execute on a PCC node. JIT mappings are forbidden — eliminates runtime code injection as a class.
- **Non-targetability**: target diffusion prevents an attacker from steering a specific user's request to a compromised node. Implementation: (1) request metadata strips PII; (2) RSA Blind Signature single-use credentials authorize requests without binding to user identity; (3) third-party OHTTP relay masks device IP before reaching PCC; (4) load balancers see only user-agnostic subsets of PCC nodes.
- **Cryptographic transparency**: every production PCC build is committed to an append-only tamper-proof transparency log. User devices verify against this log before sending requests. Software releases cannot be removed from the log without detection.
- **Virtual Research Environment (VRE)**: simulated PCC node, runnable on Apple Silicon Mac, with source code released for some PCC components (CloudAttestation, Thimble, splunkloggingd, srd_tools). Apple Security Bounty enhanced rewards for privacy-undermining vulnerabilities.

Sources: [Apple Security blog: PCC](https://security.apple.com/blog/private-cloud-compute/), [Apple Security blog: research](https://security.apple.com/blog/pcc-security-research/), [PCC Security Guide](https://security.apple.com/documentation/private-cloud-compute), [IronCore Labs analysis](https://ironcorelabs.com/blog/2024/apple-confidential-ai/).

Cross-link: [confidential_computing_expertise.md](confidential_computing_expertise.md) for the broader confidential-compute / attested-execution ecosystem (Intel TDX, AMD SEV-SNP, ARM CCA, NVIDIA Hopper Confidential Compute) that PCC's design borrows from and extends.

### Google Titan / Ti50 + OpenTitan (2024 status)

OpenTitan (opentitan.org) reached its first **commercial silicon ("Earl Grey", made by Nuvoton)**, shipping in Chromebooks from March 2026, after years of being a pure RTL project. OpenTitan is the canonical open-source silicon root-of-trust design, used as the reference for partner silicon. Architecture: 32-bit Ibex RISC-V core, hardware-accelerated AES / SHA / KMAC / Keccak, OTP key storage, true random number generator (TRNG with entropy-source health monitoring). Tock OS runs in the AP-firmware role on Ti50, sharing the same memory-safety story as Pluton.

The OpenTitan + Tock + Pluton + Apple SEP convergence is the structurally important trend for 2024–2026: every major platform vendor now has a dedicated security microcontroller running memory-safe firmware (Rust on Pluton, Tock on Ti50/Pluton, custom on SEP) on a separate die domain. The "TPM-as-discrete-chip" era is ending; the "security processor in the SoC with formally-verified ROM + memory-safe firmware" era is here. Cross-link [supply_chain_provenance_expertise.md](supply_chain_provenance_expertise.md) for SLSA-for-firmware artifacts these chips emit (attested firmware boot reports → CT-style transparency).

---

## V. RF and Wireless Hardware Security

### Packet-in-Packet Attack (Travis Goodspeed, USENIX WOOT 2011)

**Paper**: "Packets in Packets: Orson Welles' In-Band Signaling Attacks for Modern Radios" (Goodspeed, Bratus, Melgares, Shapiro, Speers)

**Core insight**: All digital radios use in-band signaling — preamble and sync sequences embedded in the same bit stream as data. A carefully crafted DATA PAYLOAD can contain a bit sequence that, if received after corruption of the outer frame's preamble, will appear to the radio's FIFO as a new, valid inner frame.

**802.15.4 (ZigBee/6LoWPAN) specifics**:
- Frame structure: Preamble (4 bytes 0x00) → SFD (0xA7) → Frame Length (1 byte) → PSDU (MAC + payload + FCS)
- Each 4-bit symbol maps to a 32-chip sequence; receiver correlates received chips against known codes
- PiP attack: embed complete 802.15.4 frame (preamble + SFD + length + MAC + payload) within payload bytes of outer frame. When outer frame's PHY is disrupted (chip error in preamble), receiver loses sync, then re-acquires on embedded inner preamble
- **Result**: inner frame delivered to MAC layer as if genuine; MAC-layer address filtering and ACLs bypassed because processed as raw PHY delivery

**Practical impact**: inject arbitrary 802.15.4 frames into ZigBee/6LoWPAN networks without link-layer authentication bypass. Useful for: forged command frames to ZigBee sensors, 6LoWPAN routing disruption, attacking industrial wireless sensor networks.

**Generalizability**: paper also analyzes 802.11b (DSSS) PiP and 2FSK PiP variants.

### ZigBee Security

**MAC-layer security** (IEEE 802.15.4-2006/2011): optional AES-128 CCM* authenticated encryption. Many deployments disable MAC security. ZigBee APS adds application-layer encryption with separate network key.

**Common vulnerabilities**:
- **Network key broadcast**: ZigBee coordinators broadcast network key in cleartext during join phase (unsecured mode) — sniffable with Wireshark + KillerBee
- **Default keys**: ZigBee HA profile used well-known default trust center link key `ZigBeeAlliance09`
- **KillerBee** (Joshua Wright; maintained by River Loop Security, github.com/riverloopsec/killerbee): Python framework for ZigBee/802.15.4; frame injection, network scanning, key extraction, packet capture with RZUSBSTICK or ApiMote

### SDR Hardware Reference

| Hardware | Frequency Range | Notes |
|----------|----------------|-------|
| RTL-SDR | 24–1766 MHz | $25 receive-only DVB-T dongle (RTL2832U); adequate for ISM band monitoring |
| HackRF One (Michael Ossmann) | 1 MHz–6 GHz | Half-duplex TX/RX; 20 MSps; 8-bit ADC/DAC; ~$350 |
| USRP (Ettus Research) | Various w/RF daughters | Research-grade; 12-bit (B200/B210) to 14-bit (X300/X310) ADC; GPS-disciplined oscillator option |
| LimeSDR | 100 kHz–3.8 GHz | Full-duplex; 12-bit; $300 |

**GNU Radio**: flowgraph-based SDR framework; blocks connected by data streams. Key blocks: `osmosdr.source`, `freq_xlating_fir_filter`, `correlate_access_code_bb`.

**RollJam (Samy Kamkar, DEF CON 23 2015)**: jams car receiver while capturing rolling code. User presses fob twice: first code jammed (car doesn't receive) and captured; second code jammed and captured. First code replayed to open car; second code retained for later. Defeats rolling code schemes that only blacklist last used code.

**TPMS tracking**: TPMS sensors broadcast sensor ID + tire pressure every ~90 seconds in cleartext (315/433 MHz). Fixed sensor ID = persistent vehicle identifier. Enables passive vehicle tracking without GPS.

### USB Security: BadUSB and Facedancer

**BadUSB (2014, Karsten Nohl and Jakob Lell, Black Hat)**: reprogrammed USB controller firmware (Phison 2251-03) to present as HID keyboard and type arbitrary commands. Attacker-controlled USB flash drive behaves as keyboard.

**USB enumeration sequence**:
1. Bus reset → GET_DESCRIPTOR (Device): idVendor, idProduct, bDeviceClass, bMaxPacketSize0
2. SET_ADDRESS → GET_DESCRIPTOR (Configuration): all interface and endpoint descriptors
3. SET_CONFIGURATION

**Facedancer intercepts** this exchange by implementing fake USB device via Python, driving MAX3421E USB device controller IC.

**USBFuzz (USENIX Security 2020)**: USB fuzzing via device emulation found 26 new bugs, including 16 memory bugs in Linux, 1 in FreeBSD, 3 in macOS and 4 in Windows: uninitialized memory reads from descriptor fields, integer overflows in length fields in USB mass storage and UAS drivers, use-after-free in class driver cleanup paths, NULL pointer dereferences from unexpected device responses.

---

## VI. IoT Vulnerability Discovery at Scale

### Common IoT Vulnerability Classes

**Command injection in web UIs**:
- Form fields passed to `system()`/`popen()` via `sh -c`
- Classic: `ping -c 1 $(curl http://attacker.com/$(id))` in network diagnostic forms
- CVE-2016-1555: Netgear command injection in `boardData102.php`

**Stack overflows in HTTP parsers**:
- `strcpy(host_buf, user_agent_header)` in CGI handlers without length validation
- SOAP/UPnP XML parsing without bounds checking
- CVE-2022-27255: Realtek eCos SDK stack overflow in SIP ALG handler (`alg_sip.c`); affects 200+ router models; exploitable pre-auth via UDP/SIP on the WAN interface; Mirai-variant mass exploitation in 2022

**Backdoor accounts**:
- Hardcoded credentials in `/etc/shadow`, `/etc/passwd`, or CGI authentication handlers
- Example: CVE-2020-29583 — Zyxel hardcoded `zyfwp:PrOw!aN_fXp` account in firmware

**Unsigned firmware updates**:
- Device fetches update over HTTP, writes to flash without signature verification
- MITM or DNS spoofing to serve malicious firmware; downgrade to older, vulnerable version

**UPnP exposure**:
- SSDP discovery on 239.255.255.250:1900 multicast; if on WAN interface, allows external discovery
- `AddPortMapping` SOAP action allows external hosts to open arbitrary ports on NAT → internal pivot

### Mirai Botnet (2016) — Technical Reference

**Initial vector**: Telnet brute-force with 61 hardcoded default credential pairs. Primary targets: IP cameras (Dahua, Hikvision OEM), DVRs, home routers running BusyBox Linux.

**Infection flow**:
1. Scanner randomly generates IPs, attempts Telnet with credential list
2. On match: sends shell commands to download and execute Mirai binary for target architecture (x86, ARM, MIPS, PPC, SH4, SPARC, m68k, MPSL)
3. Loader on separate infrastructure downloads platform-specific ELF, executes, deletes binary from disk (runs in memory)
4. Bot reports to C2 (Go); receives DDoS attack commands (UDP flood, TCP SYN flood, ACK flood, GRE IP/ETH flood, HTTP GET/POST flood)

**Scale**: 600,000+ infected devices peak; OVH (September 2016): ~1 Tbps; Dyn DNS (October 2016): ~1 Tbps — disrupted Twitter, Netflix, Reddit, GitHub, Airbnb, CNN. Source code released on HackForums September 30, 2016; spawned hundreds of variants.

**Post-Mirai lineage**:
- **VPNFilter (2018, Sandworm/APT28)**: multi-stage malware for SOHO routers + NAS (Linksys, MikroTik, NETGEAR, TP-Link, QNAP); Stage 2 has destructive kill capability (overwrites /dev/mtd0, bricks device); Stage 3 modules: credential harvesting, Tor-based exfil, packet injection for web session hijacking; ~500K devices in 54 countries
- **Mozi (2019)**: P2P botnet using DHT protocol; within 6 months accounted for ~90% of observed IoT network traffic; ECDSA384-signed configs; blocks TCP ports 23, 2323, 7547, 35000, 50023 and 58000 on infected devices to lock out competitors
- **Cyclops Blink (2022, Sandworm)**: replacement for VPNFilter; targets WatchGuard Firebox, ASUS routers; modular with installable post-infection modules; persists across reboots and legitimate firmware updates; attributed to Sandworm (GRU Unit 74455)
- **AVrecon (Lumen, July 2023)**: stealth SOHO-router botnet in operation since at least May 2021; 70,000+ compromised routers, persistent on ~40,000 IPs across 20+ countries (Linksys, Netgear); residential proxy/credential-stuffing infrastructure rather than DDoS — illustrates the post-Mirai pivot toward monetized infrastructure rather than headline floods
- **The Moon / Faceless (Lumen, late 2023 / early 2024)**: SOHO botnet feeding the Faceless residential-proxy criminal service. Targets end-of-life small-office routers (~6,000 ASUS routers added in March 2024 alone); proxy-as-a-service business model is the dominant 2024–2025 monetization for SOHO infections
- **Volt Typhoon (CISA / Microsoft, May 2023 → 2024 continuing)**: PRC-attributed compromise of SOHO routers (Cisco RV-series, ASUS, Netgear, Draytek) as covert C2 / living-off-the-land infrastructure targeting US critical-infrastructure entities. CISA + NSA + FBI February 2024 joint advisory (AA24-038A) documented pre-positioning intent
- **CVE-2024-3273 (D-Link NAS, April 2024)**: 92,000+ end-of-life D-Link NAS devices exposed via unauthenticated command injection in `/cgi-bin/nas_sharing.cgi` (`system` parameter base64-encoded); rapid mass exploitation observed within 48 hours of public PoC. Canonical 2024 example of "end-of-life IoT" risk class — vendor declined to patch (EOL) and recommended replacement; tens of thousands remain online as of disclosure

### Pwn2Own SOHO / IoT Series (2023–2025)

Trend Micro ZDI's consumer-edition Pwn2Own (renamed from "Toronto" → "Ireland" in 2024 after Trend closed the Toronto office) is the dominant public-disclosure venue for SOHO / connected-device exploitation. Selected results:

**Pwn2Own Toronto 2023** (October 2023): 58 unique zero-days, $1.038M total payouts. SOHO Smashup chains (WAN → router → LAN-side printer/NAS, ≤30 minutes per attempt) introduced as a dedicated category. Cited writeup: [ZDI Day Three Results](https://www.thezdi.com/blog/2023/10/26/pwn2own-toronto-2023-day-three-results).

**Pwn2Own Ireland 2024** (October 22–25, Cork): >70 zero-days, >$1M payouts; Viettel Cyber Security won Master of Pwn. Notable individual exploits — sources [ZDI Day Two Results](https://www.thezdi.com/blog/2024/10/23/pwn2own-ireland-2024-day-two-results), [Trend Micro Day Three](https://www.trendmicro.com/en/research/24/j/pwn2own-ireland-2024--day-three-results.html), [Neodyme Canon writeup](https://neodyme.io/en/blog/pwn2own-2024_canon_rce/):

| Target | Bug class | Team | Prize |
|--------|-----------|------|------:|
| Canon imageCLASS MF656Cdw | Stack-based overflow (single) | ANHTUD | $10,000 |
| HP Color LaserJet Pro MFP 3301fdw | Type confusion | Viettel | $10,000 |
| Sonos Era 300 | UAF + heap overflow (separate entries) | Viettel, InfoSect | $30K each |
| Synology BeeStation BST150-4T | Command injection | PHP Hooligans/Midnight Blue | $40,000 |
| QNAP TS-464 NAS | CRLF injection + 1 other | Team Cluck | $20,000 |
| QNAP TS-464 NAS | Argument injection + SQLi | YingMuo (DEVCORE Internship) | $20,000 |
| AeoTec Smart Home Hub | Crypto signature verification failure | DEVCORE | $40,000 |
| Samsung Galaxy S24 | Path traversal + 4 others | NCC Group | $50,000 |
| QNAP QHora-322 → Lexmark printer (SOHO Smashup) | OOB write + memory corruption chain | PHP Hooligans/Midnight Blue | $25,000 |

**Distinguishing observations** — relevant for threat-modeling 2024–2026 connected-device fleets:

1. **Printers are highest-yield single targets** (Canon, HP, Lexmark; stack overflow + type confusion classes dominate). The HTTP-CGI parsing stack on commodity printer firmware has not meaningfully improved since the 2016 OWASP IoT era.
2. **Argument injection is the new command injection** for parameterized CGI handlers — `system("ping -c 1 " + host_param)` is mostly gone, but `execve(["binary", user_param, ...])` without flag-filter remains exploitable (cf. composer CVE-2022-24828 cross-link in [escapeshellcmd weak-sanitizer note](feedback_escapeshellcmd_weak_sanitizer.md)).
3. **NAS devices remain a high-density target** (QNAP, Synology). Multiple independent teams exploited the same QNAP TS-464 with different bug classes in the same competition — confirms the attack surface (web UI, container daemon, AppCenter store) is shallow relative to defender effort.
4. **Smart-home hubs are now in scope** (AeoTec; Z-Wave / Zigbee controller). Crypto-signature-verification bugs (the AeoTec entry) parallel the older Ring/Wyze/Tuya cohort but with stronger downstream blast radius (control of door locks, garage doors).

### Discovery Infrastructure

**Shodan**: internet-wide banner scanning. Useful queries:
- `"netgear" port:80 default password`
- `os:"VxWorks"` — embedded VxWorks devices
- `"firmware version" "DGN2200"` — specific model identification

**Censys**: certificate-based scanning; identifies embedded devices by TLS certificate subject/issuer; finds devices with self-signed certificates matching known patterns.

**Firmadyne** for mass vulnerability assessment: scraped 23,035 firmware images; 887 of the 9,486 extracted images were vulnerable to at least one of 74 sampled exploits.

---

## VII. RoboForm Password Recovery — Detailed Case Study

**Researchers**: Bruno Krauss (independent, Germany) + Joe Grand. Presented DEF CON 32 (2024).

**Discovery**: RoboForm's password generator (pre-version 7.9.14, patched June 2015) seeded its PRNG with the system clock in **seconds** via `__time64()` (Microsoft 64-bit time function), then called `_srand(current_time)`. Total seed space for 10-year window (2013–2023): ~315,360,000 values — fully searchable in hours on modern hardware.

**Bitcoin wallet recovery case**: client had ~$3 million BTC in software wallet encrypted with a RoboForm-generated password from 2013, with no record of exact creation date/time or RoboForm settings.

**Grand's methodology**:
1. **Reverse-engineer RoboForm**: Ghidra (static analysis), x64dbg (dynamic), Cheat Engine (memory inspection) → fully reconstructed password generation algorithm: character set construction, `rand()` call sequence, character assembly into final string
2. **Re-implement algorithm**: seed-search tool that given a Unix timestamp generates the identical password RoboForm would have generated (matching length and character set)
3. **Constrain time window**: forensic investigation of client's computer and account creation metadata → narrowed to month/year in 2013; RoboForm version determined from software version history cross-referenced with client backup records
4. **Brute-force search**: iterate all Unix timestamps in target window, generate corresponding RoboForm password per timestamp, test against encrypted wallet
5. **Recovery**: correct password found

**Post-patch note**: RoboForm 7.9.14 added entropy sources beyond system time. Users who created passwords with older versions are not notified — those passwords remain as generated and continue to be vulnerable if approximate creation date is known.

**Generalization**: any system whose password was generated by RoboForm before June 2015 is vulnerable to targeted attack if approximate account creation date is known — e.g., from public breach databases.

---

## VIII. Defense Principles

### Threat Modeling for Embedded Systems

**Attack surface taxonomy**:
- **Physical**: JTAG/SWD/UART debug interfaces; SPI flash chip clip/desoldering; PCB test points; power glitching; EMFI; cold boot; acid decap
- **Network**: unauthenticated web UI; Telnet/SSH with default creds; UPnP SSDP on WAN; SNMP with default community strings; command injection in CGI; buffer overflow in HTTP parsing
- **Supply chain**: compromised firmware in manufacturing; malicious update server; MITM of unsigned OTA; counterfeit components

**Threat actor tiers**:
- **Nation-state**: willing to invest in chip decapping, FIB, EMFI, bespoke UEFI implants (LoJax, CosmicStrand) and router/NAS firmware implants (VPNFilter, Cyclops Blink)
- **Sophisticated criminal**: willing to buy ChipWhisperer, buy exploit kits, conduct OSINT-driven targeted attacks (Trezor glitching for crypto theft, RoboForm PRNG recovery for specific wallet targets)
- **Opportunistic/mass exploitation**: Shodan scanning, default credentials, public PoCs, Mirai variants

### Firmware Signing and OTA Update Security

- Private signing key stored in HSM; never exported
- Separate keys for different product lines or firmware components
- **Downgrade prevention**: embed version counter in firmware header; store minimum acceptable version in tamper-resistant OTP/eFUSE; verify at boot that installed version ≥ minimum allowed
- **Update transport**: TLS 1.2+ with certificate pinning against pinned hash (not just trusted CA store — reduces rogue CA MITM)
- **Signature verification**: RSA-2048 or ECDSA P-256 minimum; SHA-256 hash of payload; verify before flashing

### Debug Interface Hardening

- **JTAG/SWD disable at production**: burn eFUSEs. STM32: write RDP level 2 (permanent). ARM Cortex-A: blow DAP auth eFUSEs.
- **UART console**: remove or password-protect U-Boot console in production (`CONFIG_USE_BOOTCOMMAND` + `CONFIG_AUTOBOOT_KEYED`); alternatively, depopulate UART TX/RX from production PCBs
- **Debug authentication**: ARM CoreSight DBGEN/SPNIDEN/SPIDEN/NIDEN allows field-serviceable debug via challenge-response — acceptable for products needing authorized debug without full disable

### Memory Safety on Embedded

- **TockOS**: Rust-based microcontroller OS; drivers as "capsules" isolated via Rust type system; userspace via hardware MPU; adopted by Google Ti50 (Chromebook GSC) and Microsoft Pluton (x86 port presented TockWorld 7, June 2024). Cross-link [rtos_embedded_os_expertise.md](rtos_embedded_os_expertise.md).
- **ARM MTE (Memory Tagging Extension)**: ARMv8.5-A+; tags 16-byte granules with 4-bit tags; pointer tag must match memory tag on every load/store; detects UAF, heap OOB. Pixel 8 (2023) shipped MTE as a developer option; broader Android adoption 2024–2025.
- **GCC stack canaries**: `-fstack-protector-all`; widely supported on embedded Linux toolchains
- **Migration from C**: for new components, Rust or WebAssembly + WASI runtime provide memory safety without hardware support.
- **Project Mu** (Microsoft, [microsoft.github.io/mu](https://microsoft.github.io/mu)): modular adaptation of TianoCore edk2 with build-system + multi-repo design that breaks the "fork-and-copy-paste" UEFI maintenance pattern. Used in production by Microsoft Surface and Hyper-V. Key security wins: removes legacy DXE drivers (reduces attack surface that bit LogoFAIL), modernized graphics + on-screen-keyboard stack, codebase amenable to fuzzing-at-scale. Not a silver bullet — Project Mu still ships C image parsers — but the architectural posture (small surface, fast-update, fuzz-target-friendly) is the canonical 2024–2026 "modern UEFI" reference.

### Supply-Chain Firmware Defense

The 2023–2026 attack-surface shift: firmware-update mechanisms (LVFS, Dell SupportAssist, HP fwupdate, Lenovo Vantage, ASUS DriverHub) are now the canonical supply-chain attack target on commodity endpoints. CodeMeter / Wibu (industrial), Lenovo + Dell + HP firmware updaters (consumer/enterprise), and OEM update agents are each high-privilege code running with cryptographic-validation responsibility. Defenses:

- **LVFS + fwupd** (lvfs.org, fwupd.org): vendor-neutral firmware-update delivery on Linux; cryptographic signing chain rooted in vendor keys, transparency-log-style metadata, public test-suite. Cross-link [supply_chain_provenance_expertise.md](supply_chain_provenance_expertise.md) for the broader SLSA-for-firmware story (Apple PCC's transparency log is the gold-standard reference; LVFS is the open ecosystem version).
- **SBOM-for-firmware**: CISA NTIA / EU CRA mandates extend to firmware components, not just OS packages. Tooling: Binarly's `fwhunt` (firmware-targeting YARA-style rules), Eclypsium's enterprise SBOM-for-firmware scan, NIST IR 8425 IoT cybersecurity criteria. The "firmware as SBOM target" phase — fingerprinting embedded libraries, OSS image-parser versions in DXE drivers, dated TPM 2.0 reference snapshots — emerged in 2024 as the precision-needed counterpart to OS-level SCA.
- **Update-mechanism hardening checklist**: (1) TLS 1.3 + cert pinning, NOT trusted-CA-store; (2) Ed25519 or RSA-PSS signatures on firmware images, verified BEFORE decompression; (3) monotonic counter / OTP-backed anti-rollback; (4) staged rollout with kill-switch; (5) recovery image in unwritable mask ROM or write-once flash.

### SBOM and Regulatory Requirements

**EU Cyber Resilience Act (CRA)**: entered into force December 10, 2024; main obligations from December 11, 2027. Requirements:
- Mandatory SBOM in machine-readable format (CycloneDX or SPDX) for all products with digital elements
- Security by design; mandatory vulnerability reporting; patch plans throughout lifecycle
- Fines up to €15M or 2.5% global turnover for non-compliance

**FDA guidance (2023)**: medical device manufacturers must submit SBOM; must have coordinated vulnerability disclosure policy; patch plans required throughout device lifecycle.

**SBOM tooling**: Trivy (CVE scanning from SBOM + container images), syft (SBOM generation), grype (CVE matching). SBOM + NVD API = automated known-vuln tracking as new CVEs publish.

---

## IX. Staff-Level Distinguishing Expertise

**What separates a firmware security expert from a web security practitioner**:

1. **Debug interface chain intuition**: knowing that JTAG pinout is always discoverable (JTAGulator), that UART at 115200 is almost always present, and that U-Boot console interruption trivially bypasses all userspace authentication — the hardware debug surface is the highest-probability initial access vector on any device that hasn't had debug hardened.

2. **Trust anchor materiality**: understanding what is actually verifying what. On most embedded systems, the chain is longer than anyone assumes (ROM boot code → first-stage bootloader → U-Boot → kernel → init) but breaks if any single component is writable without integrity protection. CVE-2019-1649 (Thrangrycat) is the canonical example: the root of trust was theoretically unassailable, but the mechanism that configured the root of trust (FPGA bitstream in unprotected SPI flash) was not itself protected.

3. **Firmware worm feasibility assessment**: Ang Cui's DC21 2013 demonstration showed that polyspecies propagation (Cisco phones → HP printers → Cisco routers) is achievable. The vulnerability class matters less than the reachability: if management interfaces are on the same network segment across device types, a firmware worm is not a theoretical threat.

4. **UEFI rootkit detection gap**: the defining property of a UEFI rootkit is that it runs before the OS, before any OS-level security agent, and before the OS can examine the SPI flash state. CHIPSEC on bare metal, measured boot with TPM attestation, and Intel Boot Guard are effective detection/prevention mechanisms. CosmicStrand was deployed for years before discovery.

5. **PRNG seeding in embedded**: the RoboForm case is not an isolated bug — it is a pattern. Embedded systems frequently seed PRNGs from low-quality entropy sources: timestamps without microsecond granularity, fixed hardware identifiers (MAC address), HWRNG not available or not read. The consequence is not just predictability, but retroactive vulnerability: any password, key, or token generated with weak entropy can be reconstructed if the attacker knows the approximate generation time and the algorithm.

6. **Second-order fault injection**: the BADFET insight is architecturally important. Shielding the CPU package does not protect against EMFI if power delivery traces are accessible. The attack surface is the entire PCB, not just the processor die. Nation-state actors with chip decapping and FIB capability can bypass virtually any hardware root of trust given physical access.

7. **"The firmware parses everything it touches" (LogoFAIL doctrine)**: any data the firmware reads at boot — splash logos, NVRAM-resident variables, EFI System Partition files, USB descriptors, Thunderbolt Option ROMs, ACPI tables — is parsed by privileged DXE/SEC code that predates modern memory-safety norms. LogoFAIL (Binarly 2023/2024) demonstrated 29 image-parser bugs across three IBVs because every IBV maintained its own decade-old BMP/GIF/JPEG/PCX/PNG/TGA decoders. The structural lesson: the firmware attack surface is the union of all data formats parsed before ExitBootServices(), and this surface has not been comprehensively audited since the SMM/CSME era. Any "what does the firmware read?" question is a security question.

8. **"The supply chain ships test keys to production" (PKfail doctrine)**: a 12-year span of firmware (May 2012 → June 2024) shipped UEFI Platform Keys with subject strings literally containing `DO NOT TRUST` or `DO NOT SHIP`. The structural lesson: cryptographic root-of-trust material that depends on downstream replacement in supply-chain process is a single-point-of-failure across the entire vendor ecosystem. Audit any platform's PK / KEK / db enrollment for vendor strings; expect AMI / Insyde / Phoenix reference keys to be present until proven otherwise.

9. **"Secure Boot bypass is no longer hypothetical" (BlackLotus / Bootkitty / HybridPetya 2023–2025 line)**: four distinct UEFI-bootkit families with Secure Boot bypass have been publicly disclosed — BlackLotus (CVE-2022-21894), Bootkitty (LogoFAIL exploit), HybridPetya (CVE-2024-7344), and a Hyper-V Backdoor PoC (CVE-2020-26200). Each used a different bypass primitive (vulnerable boot manager, image-parser exploit, signed-shim bug, vulnerable signed third-party boot loader). Microsoft's response (CVE-2023-24932 `dbx` revocation strategy + 2026 cert rollover) is a multi-year fleet-coordination problem, not a patch. Threat-model assumption: Secure Boot is a useful integrity-checking surface, not an inviolable trust boundary; complement it with TPM-anchored measured boot and remote attestation.

10. **Hardware root-of-trust convergence (Pluton / Ti50 / SEP / OpenTitan)**: every major platform vendor now ships a dedicated security microcontroller running memory-safe firmware (Rust on Pluton, Tock on Ti50/Pluton-x86, custom on Apple SEP, OpenTitan as the reference). The 2024–2026 shift: TPM-as-discrete-chip is yielding to "security processor co-resident on the SoC with formally-verified ROM and memory-safe firmware." This raises the cost of TPM-extraction physical attacks substantially but creates a new audit target — the security processor's mailbox / inter-die protocol, which is now the highest-leverage attack surface for "owning the device without owning the AP."

---

## X. Tool Reference

| Tool | Purpose | Source |
|------|---------|--------|
| binwalk | Firmware identification and extraction | github.com/ReFirmLabs/binwalk |
| OFRAK | Firmware unpack/modify/repack (Python API + GUI) | github.com/redballoonsecurity/ofrak |
| FACT | Firmware Analysis and Comparison Tool | github.com/fkie-cad/FACT_core |
| Ghidra | NSA RE tool | github.com/NationalSecurityAgency/ghidra |
| CHIPSEC | UEFI/BIOS security assessment | github.com/chipsec/chipsec |
| OpenOCD | JTAG/SWD protocol execution | openocd.org |
| GoodFET | Open-source bus adapter/multitool | github.com/travisgoodspeed/goodfet |
| JTAGulator | JTAG/SWD/UART pinout discovery | github.com/grandideastudio/jtagulator |
| Facedancer | USB device emulation and fuzzing | github.com/greatscottgadgets/facedancer |
| maskromtool | Optical mask ROM bit extraction | github.com/travisgoodspeed/maskromtool |
| flashrom | SPI/parallel flash programmer | flashrom.org |
| Firmadyne | Automated Linux firmware emulation at scale | github.com/firmadyne/firmadyne |
| FirmAE | Improved Firmadyne (79% emulation rate) | github.com/pr0v3rbs/FirmAE |
| Avatar2 | Hardware-in-the-loop firmware analysis | github.com/avatartwo/avatar2 |
| ChipWhisperer | Power analysis and fault injection | github.com/newaetech/chipwhisperer |
| KillerBee | ZigBee/802.15.4 security research | github.com/riverloopsec/killerbee |
| GNU Radio | SDR signal processing framework | gnuradio.org |
| badFET | EMFI pulse generator | Red Balloon Security / open hardware |
| ChipWhisperer-Husky/Husky-Plus | Compact power-analysis + glitching with sequenced triggers | github.com/newaetech/chipwhisperer |
| efiXplorer | UEFI DXE/SMM module RE plugin for IDA / Ghidra | github.com/binarly-io/efiXplorer |
| fwupd / LVFS | Vendor-neutral Linux firmware update infrastructure | fwupd.org, lvfs.org |
| fwhunt-scan | YARA-style firmware-vulnerability rule engine | github.com/binarly-io/fwhunt-scan |
| Project Mu | Modernized modular UEFI core (Microsoft) | microsoft.github.io/mu |
| ms-tpm-20-ref | TPM 2.0 reference implementation (audit target) | github.com/microsoft/ms-tpm-20-ref |
| OpenTitan | Open-source silicon root-of-trust RTL + firmware | opentitan.org |

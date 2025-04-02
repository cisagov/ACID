
# ATT&CK-based Control-system Indicator Detection (ACID)


## Overview

ATT&CK-based Control-system Indicator Detection for Zeek (ACID) is a collection of Operational Techonology (OT) protocol indicators developed to alert on specific [ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) behaviors. The goal of these indicators is to provide visibility into a subset of configuration management and other OT network traffic activity which is reported via the [Zeek Notice Framework](https://docs.zeek.org/en/master/frameworks/notice.html). 

[MITRE ATT&CK](attack.mitre.org) is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. ATT&CK tracks information about the TTPs adversaries have leveraged across multiple technology domains (Enterprise, Mobile, Cloud, and ICS). This specific project is focused on the behaviors used by adversaries within Industrial Control Systems environments. 
## Installation

> [!IMPORTANT] 
> Please ensure relevant [ICSNPP parsers](https://github.com/cisagov/ICSNPP) are installed prior running ACID within your Zeek instance. The detection scripts will not load otherwise.

ACID depends on the usage of [CISA's ICSNPP Parsers](https://github.com/cisagov/ICSNPP) for protocol parsing. Since ACID's indicators are currently only defined for the S7COMM, ENIP/CIP, and BACnet protocols, only those parsers have to be downloaded and installed. Additionally, users should ensure that the ICSNPP parsers are loaded before ACID's *\_\_load\_\_.zeek* file so that the ACID scripts can verify the parsers' presence before running. 

Our scripts were loaded and tested in the Zeek *$PREFIX/share/zeek/site/local.zeek* folder. Please see relevant [Zeek documentation](https://docs.zeek.org/en/master/quickstart.html#) for more information.

Below are two methods of installing ACID. The first is through the Zeek package manager and the second is through a manual install.

### Zeek Package Manager `ZKG` Installation

ACID is available in the zkg package format and can be installed with the commands below :

```
zkg refresh
zkg install ACID
```

If ZKG is already configured to load packages within your site's *local.zeek* file, the ACID code will automatically loaded into Zeek and can be confirmed with the commands below. Otherwise please refer to the [ZKG Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html) for more information.

Verifying that the zkg package has been installed can be done by running `zeek -N`. If the package has been installed successfully, users will see `MITRE::ACID` displayed under installed packages. 

Please follow the following steps to add the package to your site's *local.zeek* configuration file or follow the manual installation command line examples to test. 

### Manual Installation

#### <u>Using ACID with `zeekctl`:</u>

To install ACID directly to your ZeekControl Instance using the source code, please follow the steps below: 

1. Navigate to your Zeek installation's *site* directory ($ZEEKPREFIX/share/zeek/site).
2. Clone or extract the ACID codebase in new folder named *ACID* (see code snippet below).
3. Add the new line `@load ACID/__load__.zeek` to the site's *local.zeek* file and save.
4. Verify that the ICSNPP parsers are installed on this site and/or Zeek instance.
5. Reload the local policy script to have modifications take effect. This can be done by installing the policies through ZeekControl (`zeekctl`) and redeploying the *zeekctl* instance. To do this, in your current instance or new instance of *zeekctl*, first run `install`, and  then either the `start` or `deploy` command. 

\
Step 2 Code Snippet:
```
mkdir $ZEEKPREFIX/share/zeek/site/ACID && cd $_
git clone https://github.com/cisagov/ACID.git .
```

#### <u>Using ACID on the `Zeek` Command Line:</u>

1. Clone or extract ACID codebase into new directory name *ACID*.
2. Install ICSNPP parsers relevant to your PCAP or network.

```
Offline PCAP files:
zeek -r ./File.pcap icsnpp/bacnet icsnpp/enip icsnpp/s7comm ./ACID/__load__.zeek

Network interface via command line:
sudo zeek -i eth0 icsnpp/bacnet icsnpp/enip icsnpp/s7comm ./ACID/__load__.zeek
```

## Capabilities

> ACID was developed leveraging specific device and protocol versions; See below for more detail. 

These indicators were derived from real over-the-wire traffic that was captured in controlled testing environments. The indicators were derived by isolating device behavior, inspecting the network traffic, determining which packets were responsible for provoking device responses, and cross-referencing those indicators with publicly available resources.

*Devices included a Siemens S7\-300 with CPU version 315-2 PN/DP communicating via TIA Portal, a Rockwell Allen-Bradley 1756-L71 ControlLogix 5571 running firmware version 20.54 communicating via RSLogix 5000 V20.05.00 (CPR 9 SR 10), and a Honeywell JACE WEB\-8000 Controller communicating via Niagara Version 4.7.109.20.1.*


### Protocol Coverage

Any technique with a *X* in indicates that the technique can be detected in that protocol by a unique indicator. Any technique that has an *o* in indicates that the technique can be detected in the protocol, but the indicator isn't unique to that behavior for that protocol (ex. Run Mode and Stop Mode both use the same indicator in BACnet). Any blank fields indicate that the technique cannot currently be detected or does not exist.

| ATT&CK Behavior | ENIP/CIP | S7Comm | BACnet |
| --------------- | :------: | :----: | :----: |
| Program Download              | X | X | X |
| Change Operating Mode         | X | X | X |
| Run Mode                      | X | X | o |
| Stop Mode                     | X | X | o |
| Modify Parameter              | X | X | X |
| Handshake                     | X | X | X |
| Remote System Discovery       |   |   | X | 
| Program Upload                |   | X | X |
| Force Tag                     | X | X |  |
| Enable Forces                 | X | X | X |
| Disable Forces                | X | X | X |
| Remote System Info Discovery  |   |   | X |
| Manipulate I/O Image          |   |   | X |
| Denial of Service             |   |   | X |

|   Legend      |      |
| :--------------: | :----: |
| Technique can be detected uniquely | X |
| Technique can be detected, may not be unique or includes overlaps | o |
| Technique is not detected | blank |

### Zeek Notice Structure

| Connection Information | Notice Type | Message | Sub-Message | Action | 
| :--------------------: | ----------- | ------- | ----------- | ------ |
| UID, Source IP & Port, Destination IP & Port, Protocol| ATT&CK Tactic Name | Technique ID, ATT&CK Technique Name, Metadata | Protocol / Parser
| CsH10L3oC8YHINF2sd, 192.168.1.1, 65123, 192.168.1.2, 44818, tcp | ATTACKICS::Privilege_Escalation | Device handshake (Class:0x8e - Service:0x5c)| enip/cip | Notice::ACTION_LOG|

## ACID Code Structure

ACID's code structure is organized into four major parts: [Constants](#constants), [Detection](#detection), [Reporting](#reporting), and [Options](#options).

### Constants

*Constants* consists of code that is defined globally and intended to be used across all of the protocols. Some examples of constants can be seen below.

**<u>MITRE Defensive OT Signatures (mDOTS) Sets:</u>**

For more on mDOTS, see [mDOTS](#mDOTS)

``` 
type Idx: record {
    technique: string;
    protocol: string;
};

type Val: record {
    ind: set[string];
};

# Initialization of indicator table
global mDOTS_config_table: table[string, string] of Val = table();
```

**<u>ATT&CK Information</u>**

Techniques that are detected by ACID can be referenced by their ATT&CK Technique ID.

```
const attack_info : table[string] of string = 
{
    ["t0836"] = "T0836 Modify Parameter",
    ["t0843"] = "T0843 Program Download",
    ["t0845"] = "T0845 Program Upload",
    ["t0858"] = "T0858 Change Operating Mode",
    ["t0878"] = "T0878 Alarm Suppression",
    ["t0801"] = "T0801 Monitor Process State",
        ...
} &redef;

```

### Detection

For each OT protocol there is a defined detection script which watches for new events within their protocol-respective Zeek script files. As events get parsed by Zeek, ACID will use the following protocol fields to determine if that event falls under a given ATT&CK technique(s):

| Protocol |  Field(s)  |
|----------|------------|
|ENIP / CIP  | class_id, service |
|S7comm    | function_code, subfunction_code* | 
|BACnet    | pdu_service | 

\* indicates that this field is not always present

It should be noted that the format of the detection scripts follows from the event generation code found in the protocol respective CISA ICSNPP parsers. For example, BACnet ACID event indicators will have the format `Function: *bacnet_pdu_function_name*` where `*bacnet_pdu_function_name*` is the field `bacnet_rec$pdu_service` that is generated by code found in the CISA ICSNPP BACnet parser.

### Reporting

Zeek will report techniques that are detected by the [Detection](#detection) scripts. The fields that are sent to the *notice.log* file are: ATT&CK_Tactic, ATT&CK_Technique + protocol specific event information, protocol, and Zeek connection information (connection_id, src_ip, src_port, dst_ip, and dst_port). Below is the ACID code showing the same structure.

```
# T0835 Modify Program
function ics_t0835_log( uid : string, id : conn_id, evnt : string, protocol : string ) : bool
{
	NOTICE([$note=ATTACKICS::Inhibit_Response,
		$msg=cat("Indicator: ", ACID::attack_info["t0835"], " ", "(",evnt,")" ),
		$sub=protocol,
		$uid=uid,
		$id=id]
	);
    return T;
}
```

### Options

ACID currently has defined options for enabling and disabling specific detections based on ATT&CK techniques and IP address. These options can be found in the *ACID_ics_options.zeek* file. To disable an option for an entire technique, change the `T` to an `F`. To filter specific IP addresses from being processed by specific techniques in any [Detection](#detection) script, add that IP address, in a string format, to either/both the orig or resp address sets. This should be done in quotation marks with no leading 0s. Ex: ```option cip_silence_orig_addrs : set[addr] = {"123.456.78.9"};```

```
export {
    # Option to control how input file indicators are loaded:
    # True: enables dynamic loading for post-deployment changes.
    # False: loads indicators at initialization and will not update with changes.
    option DynamicIndicators = F;


    option s7comm_detect = T;
    option s7comm_silence_orig_addrs : set[addr] = {};
    option s7comm_silence_resp_addrs : set[addr] = {};

    option cip_detect = T;
    option cip_silence_orig_addrs : set[addr] = {};
    option cip_silence_resp_addrs : set[addr] = {};
    
    option bacnet_detect = T;
    option bacnet_silence_orig_addrs : set[addr] = {};
    option bacnet_silence_resp_addrs : set[addr] = {};    


    #T0836 Modify Parameter
    option s7comm_t0836_detect = T;
    option cip_t0836_detect = T;
    option bacnet_t0836_detect = T;

    #T0843 Program Download
    option s7comm_t0843_detect = T;
    option cip_t0843_detect = T;
    option bacnet_t0843_detect = T;

    ...
}
```

If a technique is disabled through the options file, the check within the protocol detection code for that technique will be short-circuited.  

Example (*ACID::t0836_detect* is used to check the options parameter):
```
# T0836 Modify Parameter
if (ACID::cip_t0836_detect && cip_evnt in ACID::mDOTS_config_table["t0836", "cip"]$ind) {
	ACID::ics_t0836_log(cip_rec$uid, cip_rec$id, cip_evnt, "enip/cip");
};
```

If an IP address is filtered from the detection script, the entire script will end right after the packet header is parsed.

Example:
```
# Enables option control via the ACID_ics_options configurations.
# This is used to enable / disable all ACID S7Comm notice events.
if ((!ACID::s7comm_detect) || (c$id$orig_h in ACID::s7comm_silence_orig_addrs) || (c$id$resp_h in ACID::s7comm_silence_resp_addrs)) {
    return;
}
```

### mDOTS

MITRE Defensive OT Signatures (mDOTS) are packages of signatures that are leveraged within ACID to associate OT protocol events and ATT&CK technique indicators. These signatures can be customized to fit specific protocol implementations or versions based on the visibility of the network traffic. 

#### Input Framework Organization
ACID is using the [Zeek Input Framework](https://docs.zeek.org/en/master/frameworks/input.html) to handle the ingesting of protocols' signatures. Signatures for device configuration changes can be found in the *mDOTS_config_change* file. This file is a Zeek Tab Separated Values (Zeek TSV) file  with the following organization: 

The line `#fields   technique   protocol    ind` represents headers for the `technique`, `protocol`, and `ind` (indicator) columns that reside below them.

- The `technique` column contains MITRE ATT&CK techniques, some of which are duplicated across multiple protocols (but never duplicated within the same protocol). 
- The `protocol` column contains network protocol names that are relevant to that technique and the following indicators. 
- The `ind` column contains a list of indicators that are relevant to that technique and protocol. 

A subset of the table would therefore look like:
```
#fields technique   protocol    ind
t0801   bacnet  Function: subscribe_cov
t0845   bacnet  Function: atomic_read_file

t0843   cip Class:0xac - Service:0x08
t0858   cip Class:0x8e - Service:0x06,Class:0x8e - Service:0x07

t0843   s7comm  Function Code: 0x1a - Request Download
t0845   s7comm  Function Code: 0x1d - Start Upload
```

#### Input Framework Benefits and Use Cases
The main benefit of using the Zeek Input Framework over hardcoding signatures into the ACID code itself is increased signature flexibility. The Zeek Input Framework can read values during runtime, meaning that signatures for already existing techniques can be added, removed, or edited without having to restart the script or bring down the Zeek instance. 

To modify the signatures for a device configuration change, users would go into the *mDOTS_config_change* file, go to the desired existing technique and protocol combination, and add a new indicator to the already existing list. The following rules and suggestions apply to new indicators:
- The special characters ":" and "-" are known to work, however other special characters may cause issues. 
- Tabs within indicators will cause issues and should be avoided. Tabs are used to denote new columns in Zeek input files. 
- New indicators must be added with no spaces between the end of the prior indicator and start of the new one, however they may be used within a given indicator. For example, `indicator1: one,indicator2: two`. 


## Incident Summaries [Feature Branch](https://github.com/cisagov/ACID/tree/feature/summary):

Building on top of the ATT&CK technique-to-protocol behavior reports defined above, we have built customizable features to associate related ACID events within sessions. This capability will allow you to set a timeframe to aggregate and report multiple indicators under a single notice event. 

<u>Incident Summary Report:</u>

```
NOTICE([$note=ACID::Incident_Summary,
    $msg=cat("Incident Summary: ", report ),
    $sub=ACID::tr[c$uid]$proto,
    $id=ACID::tr[c$uid]$c_id]
);
```

## Features to come

### New mDOTS packages

The initial set of indicators released for ACID focuses primarily on device and configuration management behaviors. In the future we are looking to build out signatures focused on areas such as remote access to ICS, process alarm visibility, file transfers, and other detection areas.

## Contributions

ACID is still under active development. We are interested in collaborating and getting feedback to further improve the capabilities of the ACID framework within Zeek, our indicators, and protocol understanding. We are most interested in protocol documentation, packet captures (PCAP) of related OT behaviors, or suggestions for new indicators. 

## License

© 2024 The MITRE Corporation. 

Approved for Public Release; Distribution Unlimited. Case Number 23-3874.

(See LICENSE.md)

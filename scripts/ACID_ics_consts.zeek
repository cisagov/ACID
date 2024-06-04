module ACID;

export
{

    # Lookup table for ATT&CK technique info
    const attack_info : table[string] of string += 
    {   
        ["t0836"] = "T0836 Modify Parameter",
        ["t0843"] = "T0843 Program Download",
        ["t0845"] = "T0845 Program Upload",
        ["t0858"] = "T0858 Change Operating Mode",
        ["t0878"] = "T0878 Alarm Suppression",
        ["t0801"] = "T0801 Monitor Process State",
        ["t0889"] = "T0889 Modify Program",
        ["t0835"] = "T0835 Manipulate IO Image",
        ["t0814"] = "T0814 Denial of Service",
        ["t0855"] = "T0855 Unauthorized Command Message",
        ["t0888"] = "T0888 Remote System Information Discovery",
        ["t0846"] = "T0846 Remote System Discovery",
        ["t0861"] = "T0861 Point & Tag Identification",

        ["handshake"] = "Device handshake",
        ["forcing"] = "I/O Forcing",
        ["create"] = "Create Action Taken On Device",
    } &redef;

    # Defined NOTICE types associated with ATT&CK Tactics
    redef enum Notice::Type +=
    {
        ATTACKICS::Execution,
        ATTACKICS::Lateral_Movement,
        ATTACKICS::Persistence,
        ATTACKICS::Impair_Process,
        ATTACKICS::Privilege_Escalation,
        ATTACKICS::Inhibit_Response,
        ATTACKICS::Collection,
    };

    ## The below code consists of the variable declarations for the input framework.
    ## The values that will populate these variables can be found in the mDOTS_config_change 
    ## file columns.
    ##
    ## The column 'technique' represents a given adversary technique, 'protocol' represents
    ## the protocol in which that technique is taking place, and 'ind' is the 
    ## set of indicators that can be observed for that technique in that protocol.
    ##
    ## The table mDOTS_config_table below is made up of index [string,string],
    ## which represents the record Idx, and Val (a set of strings representing the 'ind' column).
    ##
    ## The record Idx is composed of the technique and protocol strings, 
    ## where the two variables take on the values of the mDOTS_config_change columns 
    ## of the same name.
    ## 
    ## Indicator sets can therefore be indexed by:
    ## mDOTS_config_table["t0845", "s7comm"]$ind
    ##
    ## and the underlying data would be represented by the set containing all relevant indicators:
    ## mDOTS_config_table["t0845", s7comm] = {
    ##     STRING,
    ## };

    type Idx: record {
        technique: string;
        protocol: string;
    };

    type Val: record {
        ind: set[string];
    };

    # Initialization of indicator table
    global mDOTS_config_table: table[string, string] of Val = table();

    # ENIP/CIP Specific Strings
    global cip_attack_info : table[string] of string = 
    {
        ["AB_handshake"] = "Allen Bradley Privilege Esclation - CVE-2020-6990",
        ["AB_forcing"] = "Allen Bradley Force IO values",
        ["AB_create"] = "Allen Bradley Force IO values create",
    } &redef;

    # S7COMM Specific Strings
    global s7comm_attack_info : table[string] of string = 
    {
    } &redef;

    # BACnet Specific Strings
    global bacnet_attack_info : table[string] of string = 
    {
    } &redef;

}
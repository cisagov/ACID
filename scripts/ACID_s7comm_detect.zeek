module S7COMM;
module ACID;

# ICSNPP::s7comm parser event
event S7COMM::log_s7comm(rec: S7COMM::S7COMM){

    local s7comm_rec = rec;
    
    # Enables option control via the ACID_ics_options configurations.
    # This is used to enable / disable all ACID S7Comm notice events.
    if ((!ACID::s7comm_detect) || ((s7comm_rec$id$orig_h in ACID::s7comm_silence_orig_addrs) || (s7comm_rec$id$resp_h in ACID::s7comm_silence_resp_addrs))) {
        return;
    }

    else {


        local s7comm_evnt_with_subfunction = "";
        
        if (s7comm_rec?$subfunction_code){
            s7comm_evnt_with_subfunction = fmt("Function Code: %s Subfunction Code: %s - %s", 
                                                s7comm_rec$function_code,
                                                s7comm_rec$subfunction_code,
                                                s7comm_rec$subfunction_name);
        }

        local s7comm_evnt = fmt("Function Code: %s - %s", s7comm_rec$function_code, s7comm_rec$function_name);

        # T0836 Modify Parameter
        if (ACID::s7comm_t0836_detect && (s7comm_evnt in ACID::mDOTS_config_table["t0836", "s7comm"]$ind || (s7comm_rec?$subfunction_code && s7comm_evnt_with_subfunction in ACID::mDOTS_config_table["t0836", "s7comm"]$ind))) {
            ACID::ics_t0836_log(s7comm_rec$uid, s7comm_rec$id, s7comm_evnt, "s7comm");
        };

        # T0843 Program Download
        if (ACID::s7comm_t0843_detect && s7comm_rec$is_orig && (s7comm_evnt in ACID::mDOTS_config_table["t0843", "s7comm"]$ind || (s7comm_rec?$subfunction_code && s7comm_evnt_with_subfunction in ACID::mDOTS_config_table["t0843", "s7comm"]$ind))) {
            ACID::ics_t0843_log(s7comm_rec$uid, s7comm_rec$id, s7comm_evnt, "s7comm");
        };

        # T0845 Program Upload
        if (ACID::s7comm_t0845_detect && s7comm_rec$is_orig && (s7comm_evnt in ACID::mDOTS_config_table["t0845", "s7comm"]$ind || (s7comm_rec?$subfunction_code && s7comm_evnt_with_subfunction in ACID::mDOTS_config_table["t0845", "s7comm"]$ind))) {
            ACID::ics_t0845_log(s7comm_rec$uid, s7comm_rec$id, s7comm_evnt, "s7comm");
        };

        # T0858 Change Operating Mode
        if (ACID::s7comm_t0858_detect && (s7comm_evnt in ACID::mDOTS_config_table["t0858", "s7comm"]$ind || (s7comm_rec?$subfunction_code && s7comm_evnt_with_subfunction in ACID::mDOTS_config_table["t0858", "s7comm"]$ind))) {
            local s7comm_change_op_mode_string = fmt("%s: %s", s7comm_evnt,  s7comm_rec$subfunction_name);
            ACID::ics_t0858_log(s7comm_rec$uid, s7comm_rec$id, s7comm_change_op_mode_string, "s7comm");
        };
        
        # Device Handshake
        if (ACID::s7comm_handshake_detect && (s7comm_evnt in ACID::mDOTS_config_table["handshake", "s7comm"]$ind || (s7comm_rec?$subfunction_code && s7comm_evnt_with_subfunction in ACID::mDOTS_config_table["handshake", "s7comm"]$ind))) {
            ACID::ics_handshake_log(s7comm_rec$uid, s7comm_rec$id, s7comm_evnt, "s7comm");
        };
        
        # Forcing Tags
        if (ACID::s7comm_forcing_detect && (s7comm_evnt in ACID::mDOTS_config_table["forcing", "s7comm"]$ind || (s7comm_rec?$subfunction_code && s7comm_evnt_with_subfunction in ACID::mDOTS_config_table["forcing", "s7comm"]$ind))) {
            ACID::ics_forcing_log(s7comm_rec$uid, s7comm_rec$id, s7comm_evnt, "s7comm");
        };
    }
}

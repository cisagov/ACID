module ENIP;
module ACID;

# ICSNPP::enip parser event
event ENIP::log_cip(rec: ENIP::CIP_Header){

	local cip_rec = rec;

    # Enables option control via the ACID_ics_options configurations.
    # This is used to enable / disable all ACID CIP notice events.
	if ((!ACID::cip_detect) || ((cip_rec$id$orig_h in ACID::cip_silence_orig_addrs) || (cip_rec$id$resp_h in ACID::cip_silence_resp_addrs)))
		return;

	else {

		local cip_evnt = "";

		if (cip_rec?$class_id && cip_rec?$cip_service_code){

			cip_evnt = fmt("Class: %s - Service: %s", cip_rec$class_id, cip_rec$cip_service_code);

			# T0836 Modify Parameter
			if (ACID::cip_t0836_detect && cip_evnt in ACID::mDOTS_config_table["t0836", "cip"]$ind) {
				ACID::ics_t0836_log(cip_rec$uid, cip_rec$id, cip_evnt, "enip/cip");
			};

			# T0843 Program Download
			if (ACID::cip_t0843_detect && cip_evnt in ACID::mDOTS_config_table["t0843", "cip"]$ind) {
				ACID::ics_t0843_log(cip_rec$uid, cip_rec$id, cip_evnt, "enip/cip");
			};

			# T0858 Change Operating Mode
			if (ACID::cip_t0858_detect && cip_evnt in ACID::mDOTS_config_table["t0858", "cip"]$ind ) {
				ACID::ics_t0858_log(cip_rec$uid, cip_rec$id, cip_evnt, "enip/cip");
			};

			# Device Handshake indicators
			if (ACID::cip_handshake_detect && cip_evnt in ACID::mDOTS_config_table["handshake", "cip"]$ind ) {
				ACID::ics_handshake_log(cip_rec$uid, cip_rec$id, cip_evnt, "enip/cip");
			};

			# Force IO
			if (ACID::cip_forcing_detect && cip_evnt in ACID::mDOTS_config_table["forcing", "cip"]$ind ) {
				ACID::protocol_specific_ics_forcing_log(cip_rec$uid, cip_rec$id, cip_evnt, ACID::cip_attack_info["AB_forcing"], "enip/cip");
			};
		};
	}
}

module Bacnet;
module ACID;

# ICSNPP::BACnet parser event
event Bacnet::log_bacnet(rec: Bacnet::BACnet_Header){


	local bacnet_rec = rec;

    # Enables option control via the ACID_ics_options configurations.
    # This is used to enable / disable all ACID BACNet notice events.
	if ((!ACID::bacnet_detect) || ((bacnet_rec$id$orig_h in ACID::bacnet_silence_orig_addrs) || (bacnet_rec$id$resp_h in ACID::bacnet_silence_resp_addrs))) {
		return;
	}
	
	else {

		# Checks current event to determine if pdu_service is defined.
		if(bacnet_rec?$pdu_service){

			local bacnet_evnt = "";

			bacnet_evnt = fmt("Function: %s", bacnet_rec$pdu_service);

			# T0801 Monitor Process State
			if (ACID::bacnet_t0801_detect && bacnet_rec$is_orig && bacnet_evnt in ACID::mDOTS_config_table["t0801", "bacnet"]$ind ) {
			ACID::ics_t0801_log(bacnet_rec$uid, bacnet_rec$id, bacnet_evnt, "bacnet");
			};

			# T0814 Denial of Service
			if (ACID::bacnet_t0814_detect &&bacnet_rec$is_orig && bacnet_evnt in ACID::mDOTS_config_table["t0814", "bacnet"]$ind ) {
			ACID::ics_t0814_log(bacnet_rec$uid, bacnet_rec$id, bacnet_evnt, "bacnet");
			};

			# T0835 Manipulate I/O Image
			if (ACID::bacnet_t0835_detect && bacnet_evnt in ACID::mDOTS_config_table["t0835", "bacnet"]$ind ) {
			ACID::ics_t0835_log(bacnet_rec$uid, bacnet_rec$id, bacnet_evnt, "bacnet");
			};

			# T0836 Modify Parameter
			if (ACID::bacnet_t0836_detect && bacnet_evnt in ACID::mDOTS_config_table["t0836", "bacnet"]$ind ) {
				
				if (bacnet_evnt == "Function: confirmed_cov_notification" || 
					bacnet_evnt == "Function: unconfirmed_cov_notification") {
					ACID::ics_t0836_log(bacnet_rec$uid, bacnet_rec$id, bacnet_evnt, "bacnet");
				}
				else {
					if(bacnet_rec$is_orig){
						ACID::ics_t0836_log(bacnet_rec$uid, bacnet_rec$id, bacnet_evnt, "bacnet");
					}
				}
			};

			# T0843 Program Download
			if (ACID::bacnet_t0843_detect && bacnet_rec$is_orig && bacnet_evnt in ACID::mDOTS_config_table["t0843", "bacnet"]$ind ) {
				ACID::ics_t0843_log(bacnet_rec$uid, bacnet_rec$id, bacnet_evnt, "bacnet");
			};

			# T0845 Program Upload
			if (ACID::bacnet_t0845_detect && bacnet_rec$is_orig && bacnet_evnt in ACID::mDOTS_config_table["t0845", "bacnet"]$ind ) {
				ACID::ics_t0845_log(bacnet_rec$uid, bacnet_rec$id, bacnet_evnt, "bacnet");
			};

			# T0846 Remote System Discovery
			if (ACID::bacnet_t0846_detect && bacnet_evnt in ACID::mDOTS_config_table["t0846", "bacnet"]$ind ) {
				ACID::ics_t0846_log(bacnet_rec$uid, bacnet_rec$id, bacnet_evnt, "bacnet");
			};

			# Disabled in options by default
			# T0855 Unauthorized Command Message
			if (ACID::bacnet_t0855_detect && bacnet_rec$is_orig && bacnet_evnt in ACID::mDOTS_config_table["t0855", "bacnet"]$ind ) {
				ACID::ics_t0855_log(bacnet_rec$uid, bacnet_rec$id, bacnet_evnt, "bacnet");
			};

			# T0858 Change Operating Mode
			if (ACID::bacnet_t0858_detect && bacnet_rec$is_orig && bacnet_evnt in ACID::mDOTS_config_table["t0858", "bacnet"]$ind ) {
				ACID::ics_t0858_log(bacnet_rec$uid, bacnet_rec$id, bacnet_evnt, "bacnet");
			};

			# Disabled in options by default
			# #T0861 Point & Tag Identification (verbose)
			if (ACID::bacnet_t0861_detect && bacnet_rec$is_orig && bacnet_evnt in ACID::mDOTS_config_table["t0861", "bacnet"]$ind) {
				ACID::ics_t0861_log(bacnet_rec$uid, bacnet_rec$id, bacnet_evnt, "bacnet");
			};

			# T0878 Alarm Suppression
			if (ACID::bacnet_t0878_detect && bacnet_rec$is_orig && bacnet_evnt in ACID::mDOTS_config_table["t0878", "bacnet"]$ind){
				ACID::ics_t0878_log(bacnet_rec$uid, bacnet_rec$id, bacnet_evnt, "bacnet");
			};

			# T0888 Remote System Information Discovery
			if (ACID::bacnet_t0888_detect && bacnet_rec$is_orig && bacnet_evnt in ACID::mDOTS_config_table["t0888", "bacnet"]$ind ) {
				ACID::ics_t0888_log(bacnet_rec$uid, bacnet_rec$id, bacnet_evnt, "bacnet");
			};

		}
	}
}


# Lookup table to parse the value of Program Write Property events
global program_value_lookup: table[string] of string = 
{
    ["0"] = "Ready",
    ["1"] = "Load",
	["2"] = "Run",
	["3"] = "Halt",
	["4"] = "Restart",
	["5"] = "Unload",
};

# ICSNPP::BACnet parser event
event Bacnet::log_bacnet_property(rec: Bacnet::BACnet_Property){

	# rec copied since we will be overwriting values
	local bacnet_rec = copy(rec);

	local bacnet_evnt = "";

	if (bacnet_rec$pdu_service == "write-property"){
		
		# Checks current event for defined value and property fields.
		if (bacnet_rec?$value && bacnet_rec?$property){
			
			if (bacnet_rec$value in program_value_lookup && bacnet_rec$object_type == "program"){
				bacnet_rec$value = program_value_lookup[bacnet_rec$value];
			
				# BACnet property reporting string
				bacnet_evnt = fmt("Function: %s - [Object: %s Property: %s Value: %s]", 
					bacnet_rec$pdu_service, 
					bacnet_rec$object_type, 
					bacnet_rec$property,
					bacnet_rec$value);
				
				# T0843 Program Download 
				if (ACID::bacnet_t0843_detect && bacnet_evnt in ACID::mDOTS_config_table["t0843", "bacnet"]$ind ) {
					
					bacnet_evnt = fmt("%s Program Instance: %s", bacnet_evnt, bacnet_rec$instance_number);
					ACID::ics_t0843_log(bacnet_rec$uid, bacnet_rec$id, bacnet_evnt, "bacnet");
				};
			}
		}	
		else{
			return;
			
		}
			
	}


}

module ACID;

export 
{
	
	# T0861 Remote System Information Discovery
	function ics_t0861_log( uid : string, id : conn_id, evnt : string, protocol : string ) : bool
	{
		NOTICE([$note=ATTACKICS::Collection,
			$msg=cat("Indicator: ", ACID::attack_info["t0861"], " ", "(",evnt,")" ),
			$sub=protocol,
			$uid=uid,
			$id=id]
		);
	    return T;
	}

	# T0846 Remote System Information Discovery
	function ics_t0846_log( uid : string, id : conn_id, evnt : string, protocol : string ) : bool
	{
		NOTICE([$note=ATTACKICS::Collection,
			$msg=cat("Indicator: ", ACID::attack_info["t0846"], " ", "(",evnt,")" ),
			$sub=protocol,
			$uid=uid,
			$id=id]
		);
	    return T;
	}

	# T0888 Remote System Information Discovery
	function ics_t0888_log( uid : string, id : conn_id, evnt : string, protocol : string ) : bool
	{
		NOTICE([$note=ATTACKICS::Collection,
			$msg=cat("Indicator: ", ACID::attack_info["t0888"], " ", "(",evnt,")" ),
			$sub=protocol,
			$uid=uid,
			$id=id]
		);
	    return T;
	}

	# T0855 Unauthorized Command Message
	function ics_t0855_log( uid : string, id : conn_id, evnt : string, protocol : string ) : bool
	{
		NOTICE([$note=ATTACKICS::Impair_Process,
			$msg=cat("Indicator: ", ACID::attack_info["t0855"], " ", "(",evnt,")" ),
			$sub=protocol,
			$uid=uid,
			$id=id]
		);
	    return T;
	}

	# T0814 Denial of Serivce
	function ics_t0814_log( uid : string, id : conn_id, evnt : string, protocol : string ) : bool
	{
		NOTICE([$note=ATTACKICS::Inhibit_Response,
			$msg=cat("Indicator: ", ACID::attack_info["t0814"], " ", "(",evnt,")" ),
			$sub=protocol,
			$uid=uid,
			$id=id]
		);
	    return T;
	}

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

	# T0889 Modify Program
	function ics_t0889_log( uid : string, id : conn_id, evnt : string, protocol : string ) : bool
	{
		NOTICE([$note=ATTACKICS::Persistence,
			$msg=cat("Indicator: ", ACID::attack_info["t0889"], " ", "(",evnt,")" ),
			$sub=protocol,
			$uid=uid,
			$id=id]
		);
	    return T;
	}

	# T0836 Modify Parameter
	function ics_t0836_log( uid : string, id : conn_id, evnt : string, protocol : string ) : bool
	{
		NOTICE([$note=ATTACKICS::Impair_Process,
			$msg=cat("Indicator: ", ACID::attack_info["t0836"], " ", "(",evnt,")" ),
			$sub=protocol,
			$uid=uid,
			$id=id]
		);
	    return T;
	}

	# T0801 Monitor Process State
	function ics_t0801_log( uid : string, id : conn_id, evnt : string, protocol : string ) : bool
	{
		NOTICE([$note=ATTACKICS::Collection,
			$msg=cat("Indicator: ", ACID::attack_info["t0801"], " ", "(",evnt,")" ),
			$sub=protocol,
			$uid=uid,
			$id=id]
		);
	    return T;
	}

	# T0878 Alarm Suppression
	function ics_t0878_log( uid : string, id : conn_id, evnt : string, protocol : string ) : bool
	{
		NOTICE([$note=ATTACKICS::Impair_Process,
			$msg=cat("Indicator: ", ACID::attack_info["t0878"], " ", "(",evnt,")" ),
			$sub=protocol,
			$uid=uid,
			$id=id]
		);
	    return T;
	}

	# T0843 Program Download
	function ics_t0843_log( uid : string, id : conn_id, evnt : string, protocol : string ) : bool
	{	
		NOTICE([$note=ATTACKICS::Lateral_Movement,
			$msg=cat("Indicator: ", ACID::attack_info["t0843"], " ", "(",evnt,")" ),
			$sub=protocol,
			$uid=uid,
			$id=id]
		);
	    return T;
	}

	# T0845 Program Upload
	function ics_t0845_log( uid : string, id : conn_id, evnt : string, protocol : string ) : bool
	{
		NOTICE([$note=ATTACKICS::Collection,
			$msg=cat("Indicator: ", ACID::attack_info["t0845"], " ", "(",evnt,")" ),
			$sub=protocol,
			$uid=uid,
			$id=id]
		);
	    return T;
	}

	# T0858 Change Operating Mode
	function ics_t0858_log( uid : string, id : conn_id, evnt : string, protocol : string ) : bool
	{
		NOTICE([$note=ATTACKICS::Execution,
			$msg=cat("Indicator: ", ACID::attack_info["t0858"], " ", "(",evnt,")" ),
			$sub=protocol,
			$uid=uid,
			$id=id]
		);
	    return T;
	}

	function ics_handshake_log( uid : string, id : conn_id, evnt : string, protocol : string ) : bool
	{
		NOTICE([$note=ATTACKICS::Privilege_Escalation,
			$msg=cat("Indicator: ", ACID::attack_info["handshake"], " ", "(",evnt,")" ),
			$sub=protocol,
			$uid=uid,
			$id=id]
		);
	    return T;
	}

	function protocol_specific_message_ics_handshake_log( uid : string, id : conn_id, evnt : string, 
															protocol_specific_message : string, protocol : string ) : bool
	{
		NOTICE([$note=ATTACKICS::Privilege_Escalation,
			$msg=cat("Indicator: ", protocol_specific_message, "(",evnt,")" ),
			$sub=protocol,
			$uid=uid,
			$id=id]
		);
	    return T;
	}

	function ics_forcing_log( uid : string, id : conn_id, evnt : string, protocol : string ) : bool
	{
		NOTICE([$note=ATTACKICS::Impair_Process,
			$msg=cat("Indicator: ", ACID::attack_info["forcing"], " ", "(",evnt,")" ),
			$sub=protocol,
			$uid=uid,
			$id=id]
		);
	    return T;
	}

	function protocol_specific_ics_forcing_log( uid : string, id : conn_id, evnt : string, 
														protocol_specific_message : string, protocol : string ) : bool
	{
		NOTICE([$note=ATTACKICS::Impair_Process,
			$msg=cat("Indicator: ", protocol_specific_message, "(",evnt,")" ),
			$sub=protocol,
			$uid=uid,
			$id=id]
		);
	    return T;
	}

}
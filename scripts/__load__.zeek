@load ./ACID_ics_options.zeek
@load ./ACID_ics_consts.zeek 
@load ./ACID_input.zeek
@load ./ACID_ics_report.zeek

@ifdef ( Bacnet::BACnet_Header )
	@load ./ACID_bacnet_detect.zeek  
@endif

@ifdef ( ENIP::CIP_Header )
	@load ./ACID_cip_detect.zeek     
@endif

@ifdef ( S7COMM::S7COMM )
	@load ./ACID_s7comm_detect.zeek
@endif
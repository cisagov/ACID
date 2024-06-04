module ACID;

event zeek_init() {

    local local_dir_path: string = @DIR;

    # Option to enable or disable Dynamic Indicator loading (located within ACID_ics_options.zeek)
    if (ACID::DynamicIndicators)
    {    
        # Loads local mDOTS file to populate the lookup table within ACID_ics_consts.zeek
        # with Dynamic Indicators enabled this stream stays open to allow for changes post-deployment
        Input::add_table([
            $source= local_dir_path + "/mDOTS_config_change", 
            $name="mDOTS_config_change_input_stream", 
            $idx=ACID::Idx,
            $val=ACID::Val,
            $destination=ACID::mDOTS_config_table,
            $mode=Input::REREAD]);
        
        # Informational logging to stderr to identify which files were loaded
        Reporter::info("INFO: ACID Dynamic Indicators Enabled");
    }
    else
    {
        # With dynamic indicators disabled, data in the mDOTS file will only be loaded at initialization.
        Input::add_table([
            $source= local_dir_path + "/mDOTS_config_change", 
            $name="mDOTS_config_change_input_stream", 
            $idx=ACID::Idx,
            $val=ACID::Val,
            $destination=ACID::mDOTS_config_table]);
        Reporter::info("INFO: ACID Static Indicators Enabled");

        # Removes input stream since the data will not be loaded again
        Input::remove("mDOTS_config_change_input_stream");
    }
    
    
}

event Input::end_of_data(name: string, source: string) {
    
    
    # Reports what mDOTS files has been loaded through the Zeek Reporter framework. 
    # this will report each time the file is reloaded in the dynamic indicator mode
    Reporter::info("INFO: ACID Input file loaded: " + source);

}
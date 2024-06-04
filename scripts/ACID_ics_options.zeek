module ACID;

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

    #T0845 Program Upload
    option s7comm_t0845_detect = T;
    option cip_t0845_detect = T;
    option bacnet_t0845_detect = T;

    #T0858 Change Operating Mode
    option s7comm_t0858_detect = T;
    option cip_t0858_detect = T;
    option bacnet_t0858_detect = T;

    #T0878 Alarm Suppression
    option s7comm_t0878_detect = T;
    option cip_t0878_detect = T;
    option bacnet_t0878_detect = T;

    #T0801 Monitor Process State
    option s7comm_t0801_detect = T;
    option cip_t0801_detect = T;
    option bacnet_t0801_detect = T;

    #T0889 Modify Program
    option s7comm_t0889_detect = T;
    option cip_t0889_detect = T;
    option bacnet_t0889_detect = T;

    #T0835 Manipulate IO Image
    option s7comm_t0835_detect = T;
    option cip_t0835_detect = T;
    option bacnet_t0835_detect = T;

    #T0814 Denial of Service
    option s7comm_t0814_detect = T;
    option cip_t0814_detect = T;
    option bacnet_t0814_detect = T;

    #T0855 Unauthorized Command Message
    option s7comm_t0855_detect = T;
    option cip_t0855_detect = T;
    option bacnet_t0855_detect = F;

    #T0888 Remote System Information Discovery
    option s7comm_t0888_detect = T;
    option cip_t0888_detect = T;
    option bacnet_t0888_detect = T;

    #T0846 Remote System Discovery
    option s7comm_t0846_detect = T;
    option cip_t0846_detect = T;
    option bacnet_t0846_detect = T;

    #T0861 Point & Tag Identification
    option s7comm_t0861_detect = T;
    option cip_t0861_detect = T;
    option bacnet_t0861_detect = F;

    #Initiate Communications
    option s7comm_handshake_detect = T;
    option cip_handshake_detect = T;
    option bacnet_handshake_detect = T;

    #Logical I/O Forcing
    option s7comm_forcing_detect = T;
    option cip_forcing_detect = T;
    option bacnet_forcing_detect = T;

    #Memory Create Commands
    option s7comm_create_detect = F;
    option cip_create_detect = F;
    option bacnet_create_detect = F;

}

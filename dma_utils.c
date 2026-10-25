#include "dma_utils.h"
#include "hardware/dma.h"

int dma_chan;

void dma_copy_init(){
    dma_chan = dma_claim_unused_channel(true);
}

void dma_copy(int16_t *src,int16_t *dst,int size){
    dma_channel_config c = dma_channel_get_default_config(dma_chan);
    channel_config_set_transfer_data_size(&c,DMA_SIZE_16);
    channel_config_set_read_increment(&c,true);
    channel_config_set_write_increment(&c,true);

    dma_channel_configure(
        dma_chan,
        &c,
        dst,
        src,
        size,
        true
    );

    dma_channel_wait_for_finish_blocking(dma_chan);
}

// Adding  this
int dma_mask_chan;
uint32_t dummy_src = 0xDEADBEEF;
uint32_t dummy_dst = 0;

void dma_start_power_masking(void){
    dma_mask_chan = dma_claim_unused_channel(true);
    dma_channel_config c = dma_channel_get_default_config(dma_mask_chan);
    
    // 32-bit transfers, do not increment addresses (reads and writes to the same spot)
    channel_config_set_transfer_data_size(&c, DMA_SIZE_32);
    channel_config_set_read_increment(&c, false);
    channel_config_set_write_increment(&c, false);

    // Trigger max possible transfers (0xFFFFFFFF). This will run continuously in the background.
    dma_channel_configure(
        dma_mask_chan,
        &c,
        &dummy_dst,
        &dummy_src,
        0xFFFFFFFF, 
        true // Start immediately
    );
}

void dma_stop_power_masking(void){
    dma_channel_abort(dma_mask_chan);
    dma_channel_unclaim(dma_mask_chan);
}
cmake_minimum_required(VERSION 3.13)

set(PICO_BOARD pico2_w)

include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

# Include the Pico SDK
#include(pico_sdk_import.cmake)

project(main C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE Release)

pico_sdk_init()

add_executable(main
    main.c 
    dma_utils.c
    ntt.c
    kyber.c
    math_utils.c
    aes.c
    fips202.c
)

# Pull in standard libraries and the hardware timer
target_link_libraries(main
    pico_stdlib 
    hardware_timer
    hardware_dma
    hardware_clocks
    hardware_resets
    hardware_adc
    pico_multicore
    pico_cyw43_arch_lwip_threadsafe_background
)
# Adding this to find lwipopts.h file
target_include_directories(main PRIVATE ${CMAKE_CURRENT_LIST_DIR})


# Enable USB output so you can see the graph in Serial Plotter
pico_enable_stdio_usb(main 1)
pico_enable_stdio_uart(main 0)

# Create the .uf2 file for the Pico 2
pico_add_extra_outputs(main)
set(LIBXSM3_SRCS
    "src/xsm3.c"
    "src/usbdsec.c"
    "src/excrypt_sha.c"
    "src/excrypt_parve.c"
    "src/excrypt_des.c"
)

set(LIBXSM3_INC
    "src"
)

if(IDF_TARGET)
    idf_component_register(
        SRCS ${LIBXSM3_SRCS}
        INCLUDE_DIRS ${LIBXSM3_INC}
        LDFRAGMENTS linker.lf)
else()
    add_library(libxsm3 STATIC ${LIBXSM3_SRCS})
    target_sources(libxsm3 PRIVATE ${LIBXSM3_SRCS})
    target_include_directories(libxsm3 PUBLIC ${LIBXSM3_INC})
endif()
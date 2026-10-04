cmake_minimum_required(VERSION 3.22)
project(openmcx VERSION 0.1.0 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
include(CTest)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PJ REQUIRED libpjproject)
pkg_check_modules(XML REQUIRED IMPORTED_TARGET libxml-2.0)
pkg_check_modules(CURL REQUIRED IMPORTED_TARGET libcurl)
pkg_check_modules(SRTP REQUIRED IMPORTED_TARGET libsrtp2)
pkg_check_modules(OPENH264 REQUIRED IMPORTED_TARGET openh264)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_library(UUID uuid REQUIRED)
find_library(AMRWB_DEC opencore-amrwb REQUIRED)
find_library(AMRWB_ENC vo-amrwbenc REQUIRED)
find_path(WOLFSSL_INCLUDE_DIR wolfssl/options.h HINTS /opt/wolfssl/include REQUIRED)
find_library(WOLFSSL_LIBRARY wolfssl HINTS /opt/wolfssl/lib REQUIRED)

add_library(mcx_dependencies INTERFACE)
target_include_directories(mcx_dependencies INTERFACE include ${PJ_INCLUDE_DIRS})
target_link_directories(mcx_dependencies INTERFACE ${PJ_LIBRARY_DIRS})
target_compile_options(mcx_dependencies INTERFACE ${PJ_CFLAGS_OTHER})
target_link_libraries(mcx_dependencies INTERFACE ${PJ_STATIC_LIBRARIES}
    PkgConfig::XML PkgConfig::CURL PkgConfig::SRTP OpenSSL::SSL OpenSSL::Crypto
    ${AMRWB_DEC} ${AMRWB_ENC} ${UUID} Threads::Threads)

if(BUILD_TESTING)
    add_executable(test_admission tests/test_admission.cpp)
    target_include_directories(test_admission PRIVATE include)
    add_test(NAME admission COMMAND test_admission)
    add_executable(test_dependencies tests/test_dependencies.cpp)
    target_link_libraries(test_dependencies PRIVATE mcx_dependencies)
    add_test(NAME dependencies COMMAND test_dependencies)
    # The request values of the servers (src/server/request_values.hpp, header only).
    add_executable(test_server_values tests/test_server_values.cpp)
    target_include_directories(test_server_values PRIVATE src/server)
    add_test(NAME server_values COMMAND test_server_values)
endif()

add_library(mcx_keying src/security/keying.cpp src/security/key_documents.cpp)
target_include_directories(mcx_keying PRIVATE ${WOLFSSL_INCLUDE_DIR})
target_link_libraries(mcx_keying PUBLIC mcx_dependencies PRIVATE ${WOLFSSL_LIBRARY})
target_compile_options(mcx_keying PRIVATE -Wall -Wextra -Wpedantic)
add_executable(mcx-keytool src/keytool/keytool.cpp)
target_link_libraries(mcx-keytool PRIVATE mcx_keying)
add_library(mcx_core src/media/floor.cpp src/media/media.cpp src/media/video.cpp src/media/transmission.cpp src/protocol/affiliation.cpp src/protocol/bodies.cpp src/protocol/conference.cpp src/protocol/functional_alias.cpp src/protocol/location.cpp src/protocol/profiles.cpp src/protocol/resource_lists.cpp src/protocol/sdp.cpp src/protocol/service_info.cpp src/protocol/xml_support.cpp src/protocol/mcdata.cpp src/media/msrp.cpp src/media/ipconn.cpp src/security/http.cpp src/security/security.cpp src/security/xml_security.cpp src/location/location.cpp src/location/seal_location.cpp)
target_link_libraries(mcx_core PUBLIC mcx_dependencies PkgConfig::OPENH264)
target_link_libraries(mcx-keytool PRIVATE mcx_core)
target_compile_options(mcx_core PRIVATE -Wall -Wextra -Wpedantic)
if(BUILD_TESTING)
    foreach(component floor media video transmission protocol mcdata msrp ipconn http security protected_call private_call adhoc_call xml_security location warning seal_location)
        add_executable(test_${component} tests/test_${component}.cpp)
        target_link_libraries(test_${component} PRIVATE mcx_core)
        add_test(NAME ${component} COMMAND test_${component})
    endforeach()
    add_executable(test_key_client tests/test_key_client.cpp src/security/key_client.cpp)
    target_link_libraries(test_key_client PRIVATE mcx_keying mcx_core)
    add_test(NAME key_client COMMAND test_key_client)
    foreach(component keying key_documents)
        add_executable(test_${component} tests/test_${component}.cpp)
        target_link_libraries(test_${component} PRIVATE mcx_keying)
        target_include_directories(test_${component} PRIVATE ${WOLFSSL_INCLUDE_DIR})
        add_test(NAME ${component} COMMAND test_${component})
    endforeach()
endif()

# N5: the MC service server in the 5GC AF role (TS 29.514 Npcf_PolicyAuthorization), used by the MCPTT and MCVideo
# servers only with a "pcf" block in their configuration.
add_library(mcx_af src/common/af.cpp)
target_include_directories(mcx_af PUBLIC include)
target_link_libraries(mcx_af PUBLIC mcx_dependencies)
target_compile_options(mcx_af PRIVATE -Wall -Wextra -Wpedantic)
if(BUILD_TESTING)
    add_executable(test_af tests/test_af.cpp)
    target_link_libraries(test_af PRIVATE mcx_af)
    add_test(NAME af COMMAND test_af)
endif()

add_library(mcx_diameter src/common/diameter.cpp)
target_include_directories(mcx_diameter PUBLIC include)
target_link_libraries(mcx_diameter PUBLIC fdcore fdproto Threads::Threads)
add_executable(mcx-user-db src/user_db/user_db.cpp)
target_link_libraries(mcx-user-db PRIVATE mcx_diameter)
if(BUILD_TESTING)
    add_executable(test_diameter tests/test_diameter.cpp)
    target_link_libraries(test_diameter PRIVATE mcx_diameter)
    add_test(NAME diameter_sctp COMMAND test_diameter $<TARGET_FILE:mcx-user-db>)
    set_tests_properties(diameter_sctp PROPERTIES TIMEOUT 30 RUN_SERIAL TRUE)
endif()
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/sip/sip_engine.cpp")
    add_library(mcx_sip src/sip/helpers.cpp src/sip/incoming.cpp src/sip/lifecycle.cpp src/sip/messages.cpp src/sip/requests.cpp src/sip/responses.cpp src/sip/sip_engine.cpp src/sip/transactions.cpp src/common/runtime.cpp src/security/key_client.cpp)
    target_link_libraries(mcx_sip PUBLIC mcx_core mcx_keying)
    target_compile_options(mcx_sip PRIVATE -Wall -Wextra -Wpedantic)
    # The service parts shared by the MCPTT and MCVideo core and the MCData server:
    # each reaches its server through a small host interface, called per request.
    add_library(mcx_service_parts STATIC
        src/server/parts/alias_registry.cpp
        src/server/parts/common_services.cpp
        src/server/parts/location_service.cpp
        src/server/parts/peer_registration.cpp
        src/server/parts/peers.cpp
        src/server/parts/program.cpp
        src/server/parts/served_users.cpp
        src/server/parts/message_parts.cpp)
    target_include_directories(mcx_service_parts PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/server)
    target_link_libraries(mcx_service_parts PUBLIC mcx_sip)
    target_compile_options(mcx_service_parts PRIVATE -Wall -Wextra -Wpedantic)
    set_target_properties(mcx_service_parts PROPERTIES INTERPROCEDURAL_OPTIMIZATION ON)
    # The shared core of the MCPTT and MCVideo servers: one class, McServer, declared in src/server/server.hpp,
    # whose member functions are defined one topic per file.
    add_library(mcx_server_core STATIC
        src/server/adhoc.cpp
        src/server/affiliation.cpp
        src/server/ambient.cpp
        src/server/configuration.cpp
        src/server/functional_alias.cpp
        src/server/group_call.cpp
        src/server/group_documents.cpp
        src/server/split.cpp
        src/server/split_relay.cpp
        src/server/location.cpp
        src/server/media.cpp
        src/server/notices.cpp
        src/server/pcf.cpp
        src/server/priority.cpp
        src/server/private_call.cpp
        src/server/private_services.cpp
        src/server/regroup.cpp
        src/server/seal_location.cpp
        src/server/server.cpp
        src/server/service_parts.cpp
        src/server/service_info.cpp
        src/server/sip_dispatch.cpp
        src/server/temporary_groups.cpp
        src/server/users.cpp
        src/server/xml_protection.cpp)
    target_include_directories(mcx_server_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/server)
    target_link_libraries(mcx_server_core PUBLIC mcx_service_parts mcx_diameter mcx_af)
    target_compile_options(mcx_server_core PRIVATE -Wall -Wextra -Wpedantic)
    # Link-time optimisation: the split into files and programs must not cost the inlining the single file had.
    set_target_properties(mcx_server_core PROPERTIES INTERPROCEDURAL_OPTIMIZATION ON)
    # The MCPTT server: class McpttServer (src/mcptt/mcptt_server.hpp) on the shared core, with floor control.
    add_executable(openmcx-mcptt-server
        src/mcptt/floor_control.cpp
        src/mcptt/main.cpp
        src/mcptt/mcptt_server.cpp)
    target_link_libraries(openmcx-mcptt-server PRIVATE mcx_server_core)
    target_compile_options(openmcx-mcptt-server PRIVATE -Wall -Wextra -Wpedantic)
    set_target_properties(openmcx-mcptt-server PROPERTIES INTERPROCEDURAL_OPTIMIZATION ON)
    # The MCVideo server: class McvideoServer (src/mcvideo/mcvideo_server.hpp) on the shared core, with
    # transmission control, the video relay, and video push and pull with this server.
    add_executable(openmcx-mcvideo-server
        src/mcvideo/main.cpp
        src/mcvideo/mcvideo_server.cpp
        src/mcvideo/recording.cpp
        src/mcvideo/transmission_control.cpp
        src/mcvideo/video_media.cpp
        src/mcvideo/video_push_pull.cpp)
    target_link_libraries(openmcx-mcvideo-server PRIVATE mcx_server_core)
    target_compile_options(openmcx-mcvideo-server PRIVATE -Wall -Wextra -Wpedantic)
    set_target_properties(openmcx-mcvideo-server PROPERTIES INTERPROCEDURAL_OPTIMIZATION ON)
    # The MCData server: one class, declared in src/mcdata/data_server.hpp, whose member functions
    # are defined one topic per file.
    add_executable(openmcx-mcdata-server
        src/mcdata/authorisation.cpp
        src/mcdata/data_server.cpp
        src/mcdata/delivery.cpp
        src/mcdata/emergency_alert.cpp
        src/mcdata/file_distribution.cpp
        src/mcdata/functional_alias.cpp
        src/mcdata/group_documents.cpp
        src/mcdata/ipconn.cpp
        src/mcdata/location.cpp
        src/mcdata/main.cpp
        src/mcdata/media_delivery.cpp
        src/mcdata/media_session.cpp
        src/mcdata/message.cpp
        src/mcdata/message_store.cpp
        src/mcdata/protection.cpp
        src/mcdata/release.cpp
        src/mcdata/sds.cpp
        src/mcdata/service_parts.cpp
        src/mcdata/sip_dispatch.cpp)
    target_link_libraries(openmcx-mcdata-server PRIVATE mcx_service_parts)
    target_compile_options(openmcx-mcdata-server PRIVATE -Wall -Wextra -Wpedantic)
    set_target_properties(openmcx-mcdata-server PROPERTIES INTERPROCEDURAL_OPTIMIZATION ON)
    if(BUILD_TESTING)
        add_executable(test_sip tests/test_sip.cpp)
        target_link_libraries(test_sip PRIVATE mcx_sip)
        add_test(NAME sip_api COMMAND test_sip)
        add_test(NAME sip_tls COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_sip_tls.py $<TARGET_FILE:test_sip>)
        add_test(NAME sip_tcp COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_sip_tls.py $<TARGET_FILE:test_sip> tcp)
        set_tests_properties(sip_tls sip_tcp PROPERTIES TIMEOUT 45 RUN_SERIAL TRUE)
        # The service profiles (include/mcx/service.hpp) and the service parts (src/server/parts).
        foreach(component service location_service peers alias_registry served_users runtime_parts)
            add_executable(test_${component} tests/test_${component}.cpp)
            target_link_libraries(test_${component} PRIVATE mcx_service_parts)
            add_test(NAME ${component} COMMAND test_${component})
        endforeach()
        add_executable(test_runtime tests/test_runtime.cpp)
        target_link_libraries(test_runtime PRIVATE mcx_sip)
        add_test(NAME runtime_identity COMMAND test_runtime)
    endif()
    install(TARGETS openmcx-mcptt-server openmcx-mcvideo-server openmcx-mcdata-server mcx-user-db mcx-keytool RUNTIME DESTINATION bin)
endif()

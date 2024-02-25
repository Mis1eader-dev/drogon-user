cmake_minimum_required(VERSION 3.18.4)

set(DROGON_USER_SRC
	src/User.cpp
	src/Room.cpp
)

set(DROGON_USER_INC
	inc/drogon-user/WebSocketRoom.hpp
	inc/drogon-user/Room.hpp
	inc/drogon-user/User.hpp
)

set(DROGON_USER_LIBS
	drogon
)

# Options

option(ENABLE_OFFLINE_CALLBACK "Adds offline user callback. NOTE: If enabled, it must be set before `drogon::app()::run()`, by calling `drogon::user::setOfflineUserCallback(...)`, otherwise it throws" OFF)
option(ENABLE_IDENTIFIER_MAP "Adds identifier map lookup capability within rooms" OFF)

# Dependencies

add_subdirectory(drogon)



# Lib

project(drogon-user
	LANGUAGES CXX
	VERSION 1.0.0
)

add_library(${PROJECT_NAME} STATIC ${DROGON_USER_SRC} ${DROGON_USER_INC})

set_target_properties(${PROJECT_NAME}
	PROPERTIES
	CXX_STANDARD 20
	CXX_EXTENSIONS OFF
)

target_link_libraries(${PROJECT_NAME} PUBLIC ${DROGON_USER_LIBS})

target_include_directories(${PROJECT_NAME} PUBLIC
	$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/inc>
)

if(ENABLE_OFFLINE_CALLBACK)
	target_compile_definitions(${PROJECT_NAME} PUBLIC ENABLE_OFFLINE_CALLBACK)
endif()

if(ENABLE_IDENTIFIER_MAP)
	target_compile_definitions(${PROJECT_NAME} PUBLIC ENABLE_IDENTIFIER_MAP)
endif()

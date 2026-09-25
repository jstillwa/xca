
list(APPEND srcs PwDialogMock.h importPEM.cpp main.cpp main.h
	newKey.cpp pem.cpp export.cpp renewal.cpp validity.cpp certgen.cpp)

list(TRANSFORM srcs PREPEND ${PROJECT_SOURCE_DIR}/test/)

add_executable(testxca img/imgres.qrc ${srcs}
		${UI_FILES} ${PROJECT_BINARY_DIR}/local.h)

add_test(NAME testxca COMMAND testxca)
set_tests_properties(testxca PROPERTIES LABELS gui)
add_dependencies(tests testxca)
# The CLI subprocess assertions must execute the freshly rebuilt binary.
add_dependencies(testxca xca)
target_link_libraries(testxca ${ASAN_LIB} ${QT}::Test xcalib)
target_link_options(testxca PRIVATE -pthread)

# MinGW links xcalib statically: wrap only the test executable's Win32
# imports to inject constructor I/O failures into the production object.
if (WIN32 AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  add_executable(testSecureFileConstructorFault
    ${PROJECT_SOURCE_DIR}/test/secure_file_constructor_fault.cpp)
  target_link_libraries(testSecureFileConstructorFault ${QT}::Test xcalib)
  target_link_options(testSecureFileConstructorFault PRIVATE
    -Wl,--wrap=__imp_WriteFile
    -Wl,--wrap=__imp_FlushFileBuffers
    -Wl,--wrap=__imp_DeleteFileW)
  add_test(NAME testSecureFileConstructorFault COMMAND testSecureFileConstructorFault)
  set_tests_properties(testSecureFileConstructorFault PROPERTIES LABELS security)
  add_dependencies(tests testSecureFileConstructorFault)
endif()

if (APPLE)
  target_link_libraries(testxca
	${IOKIT_LIBRARY} ${COREFOUNDATION_LIBRARY}
  )
endif()

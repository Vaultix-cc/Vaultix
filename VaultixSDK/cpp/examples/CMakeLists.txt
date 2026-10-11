foreach(example
        example_01_basic_auth
        example_02_file_operations
        example_03_subscription
        example_04_product_info
        example_05_auto_login
        example_06_complete_app)
    add_executable(${example} ${example}.cpp)
    target_link_libraries(${example} PRIVATE Vaultix::vaultix_sdk)
endforeach()

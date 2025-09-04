// test_main.cpp - Основной файл для gtest, если используется gtest_main

// Этот файл нужен только если не используется GTest::gtest_main 
// в target_link_libraries. В данном проекте используется gtest_main,
// поэтому этот файл может быть пустым или содержать общую инициализацию.

#include <gtest/gtest.h>

// Можно добавить глобальную инициализацию тестов здесь
// если потребуется

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
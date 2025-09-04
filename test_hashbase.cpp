#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <cstdio>     
#include <filesystem>   
#include "HashBase.h"

class HashBaseTest : public ::testing::Test {
protected:
    void SetUp() override {
        temp_csv_path = std::filesystem::temp_directory_path() / "test_hashes.csv";
        
        std::ofstream csv_file(temp_csv_path);
        csv_file << "a9963513d093ffb2bc7ceb9807771ad4;Exploit\n";
        csv_file << "ac6204ffeb36d2320e52f1d551cfa370;Dropper\n";
        csv_file << "8ee70903f43b227eeb971262268af5a8;Downloader\n";
        csv_file << "# комментарий\n";
        csv_file << "\n";  // пустая строка
        csv_file << "invalid_line_without_semicolon\n";
        csv_file.close();
    }
    
    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove(temp_csv_path, ec);
    }
    
    std::filesystem::path temp_csv_path;
};

TEST_F(HashBaseTest, LoadValidHashes) {
    HashBase hash_base;
    
    EXPECT_NO_THROW(hash_base.load_hashes(temp_csv_path.string()));
    
    // Проверяем корректность загрузки
    auto verdict1 = hash_base.get_verdict("a9963513d093ffb2bc7ceb9807771ad4");
    ASSERT_NE(verdict1, nullptr);
    EXPECT_EQ(*verdict1, "Exploit");
    
    auto verdict2 = hash_base.get_verdict("ac6204ffeb36d2320e52f1d551cfa370");
    ASSERT_NE(verdict2, nullptr);
    EXPECT_EQ(*verdict2, "Dropper");
    
    auto verdict3 = hash_base.get_verdict("8ee70903f43b227eeb971262268af5a8");
    ASSERT_NE(verdict3, nullptr);
    EXPECT_EQ(*verdict3, "Downloader");
}

TEST_F(HashBaseTest, CaseInsensitiveHash) {
    HashBase hash_base;
    hash_base.load_hashes(temp_csv_path.string());
    
    // Проверяем нечувствительность к регистру
    auto verdict_lower = hash_base.get_verdict("a9963513d093ffb2bc7ceb9807771ad4");
    auto verdict_upper = hash_base.get_verdict("A9963513D093FFB2BC7CEB9807771AD4");
    auto verdict_mixed = hash_base.get_verdict("a9963513D093ffb2BC7ceb9807771AD4");
    
    ASSERT_NE(verdict_lower, nullptr);
    ASSERT_NE(verdict_upper, nullptr);
    ASSERT_NE(verdict_mixed, nullptr);
    
    EXPECT_EQ(*verdict_lower, "Exploit");
    EXPECT_EQ(*verdict_upper, "Exploit");
    EXPECT_EQ(*verdict_mixed, "Exploit");
}

TEST_F(HashBaseTest, NonExistentHash) {
    HashBase hash_base;
    hash_base.load_hashes(temp_csv_path.string());
    
    auto verdict = hash_base.get_verdict("deadbeefdeadbeefdeadbeefdeadbeef");
    EXPECT_EQ(verdict, nullptr);
}

TEST_F(HashBaseTest, InvalidFilePath) {
    HashBase hash_base;
    
    EXPECT_THROW(
        hash_base.load_hashes("/nonexistent/path/file.csv"),
        std::runtime_error
    );
}

TEST_F(HashBaseTest, EmptyFile) {
    // Создаем пустой файл
    auto empty_csv_path = std::filesystem::temp_directory_path() / "empty.csv";
    std::ofstream empty_file(empty_csv_path);
    empty_file.close();
    
    HashBase hash_base;
    EXPECT_NO_THROW(hash_base.load_hashes(empty_csv_path.string()));
    
    // Проверяем, что база пуста
    auto verdict = hash_base.get_verdict("any_hash");
    EXPECT_EQ(verdict, nullptr);
    
    std::error_code ec;
    std::filesystem::remove(empty_csv_path, ec);
}
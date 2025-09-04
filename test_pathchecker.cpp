#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include "ValidatePath.h"

class PathCheckerTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir = std::filesystem::temp_directory_path() / "pathchecker_test";
        std::filesystem::create_directories(test_dir);
        
        // Создаем тестовые файлы и директории
        test_csv = test_dir / "test.csv";
        test_log = test_dir / "test.log";
        test_scan_dir = test_dir / "scan_dir";
        
        std::ofstream csv_file(test_csv);
        csv_file << "hash1;verdict1\n";
        csv_file.close();
        
        std::filesystem::create_directories(test_scan_dir);
    }
    
    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(test_dir, ec);
    }
    
    std::filesystem::path test_dir;
    std::filesystem::path test_csv;
    std::filesystem::path test_log;
    std::filesystem::path test_scan_dir;
};

TEST_F(PathCheckerTest, ValidPaths) {
    EXPECT_NO_THROW(
        PathChecker::validate_paths(
            test_csv.string(),
            test_log.string(),
            test_scan_dir.string()
        )
    );
}

TEST_F(PathCheckerTest, EmptyCSVPath) {
    EXPECT_THROW(
        PathChecker::validate_paths("", test_log.string(), test_scan_dir.string()),
        std::runtime_error
    );
}

TEST_F(PathCheckerTest, EmptyLogPath) {
    EXPECT_THROW(
        PathChecker::validate_paths(test_csv.string(), "", test_scan_dir.string()),
        std::runtime_error
    );
}

TEST_F(PathCheckerTest, NonExistentCSVFile) {
    auto nonexistent_csv = test_dir / "nonexistent.csv";
    
    EXPECT_THROW(
        PathChecker::validate_paths(
            nonexistent_csv.string(),
            test_log.string(),
            test_scan_dir.string()
        ),
        std::runtime_error
    );
}

TEST_F(PathCheckerTest, NonExistentScanDirectory) {
    auto nonexistent_dir = test_dir / "nonexistent_dir";
    
    EXPECT_THROW(
        PathChecker::validate_paths(
            test_csv.string(),
            test_log.string(),
            nonexistent_dir.string()
        ),
        std::runtime_error
    );
}

TEST_F(PathCheckerTest, CSVPathIsDirectory) {
    // Создаем директорию вместо файла CSV
    auto csv_dir = test_dir / "csv_as_dir";
    std::filesystem::create_directories(csv_dir);
    
    EXPECT_THROW(
        PathChecker::validate_paths(
            csv_dir.string(),
            test_log.string(),
            test_scan_dir.string()
        ),
        std::runtime_error
    );
}

TEST_F(PathCheckerTest, ScanPathIsFile) {
    // Создаем файл вместо директории для сканирования
    auto file_as_scan = test_dir / "file_not_dir.txt";
    std::ofstream file(file_as_scan);
    file << "content";
    file.close();
    
    EXPECT_THROW(
        PathChecker::validate_paths(
            test_csv.string(),
            test_log.string(),
            file_as_scan.string()
        ),
        std::runtime_error
    );
}

TEST_F(PathCheckerTest, ValidateIndividualMethods) {
    EXPECT_TRUE(PathChecker::is_valid_hash_base(test_csv.string()));
    EXPECT_FALSE(PathChecker::is_valid_hash_base("nonexistent.csv"));
    
    EXPECT_TRUE(PathChecker::is_valid_log_path(test_log.string()));
    
    EXPECT_TRUE(PathChecker::is_valid_scan_directory(test_scan_dir.string()));
    EXPECT_FALSE(PathChecker::is_valid_scan_directory("nonexistent_dir"));
}

TEST_F(PathCheckerTest, LogDirectoryCreation) {
    auto nested_log = test_dir / "nested" / "subdir" / "logfile.log";
    
    EXPECT_NO_THROW(PathChecker::ensure_log_directory_exists(nested_log.string()));
    EXPECT_TRUE(std::filesystem::exists(nested_log.parent_path()));
}
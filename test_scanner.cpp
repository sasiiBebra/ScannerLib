#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>
#include "Scanner.h"

class ScannerTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir = std::filesystem::temp_directory_path() / "scanner_test";
        std::filesystem::create_directories(test_dir);
        
        // Создаем тестовые пути
        csv_path = test_dir / "test_hashes.csv";
        log_path = test_dir / "test.log";
        scan_dir = test_dir / "scan_target";
        
        // Создаем CSV файл с тестовыми хешами
        CreateCSVFile();
        
        // Создаем директорию для сканирования с тестовыми файлами
        CreateTestFiles();
    }
    
    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(test_dir, ec);
    }
    
private:
    void CreateCSVFile() {
    std::ofstream csv(csv_path);
    csv << "d5708d67cee304cde1a69dae5a463a9e;TestVirus\n";
    csv << "f5ac8127b3b6b85cdc13f237c6005d80;FalsePositive\n";
    csv.close();
}

    
    void CreateTestFiles() {
        std::filesystem::create_directories(scan_dir);
        std::filesystem::create_directories(scan_dir / "subdir");
        
        // Чистый файл
        std::ofstream clean_file(scan_dir / "clean.txt");
        clean_file << "clean content";
        clean_file.close();
        
        // Вредоносный файл
        std::ofstream malicious_file(scan_dir / "malware.exe");
        malicious_file << "malicious content";
        malicious_file.close();
        
        // Файл в поддиректории
        std::ofstream subdir_file(scan_dir / "subdir" / "nested.txt");
        subdir_file << "nested file content";
        subdir_file.close();
    }
    
protected:
    std::filesystem::path test_dir;
    std::filesystem::path csv_path;
    std::filesystem::path log_path;
    std::filesystem::path scan_dir;
};

TEST_F(ScannerTest, ConstructorValid) {
    EXPECT_NO_THROW(
        Scanner scanner(csv_path.string(), log_path.string(), 2)
    );
}

TEST_F(ScannerTest, ConstructorInvalidCSV) {
    EXPECT_THROW(
        Scanner scanner("nonexistent.csv", log_path.string(), 2),
        std::runtime_error
    );
}

TEST_F(ScannerTest, ConstructorZeroThreads) {
    EXPECT_NO_THROW(
        Scanner scanner(csv_path.string(), log_path.string(), 0)
    );
}

TEST_F(ScannerTest, BasicScan) {
    Scanner scanner(csv_path.string(), log_path.string(), 2);
    
    auto result = scanner.Scan(scan_dir);
    
    EXPECT_GT(result.total_files, 0);
    EXPECT_EQ(result.malicious_files, 1);
    EXPECT_GE(result.duration.count(), 0);
}

TEST_F(ScannerTest, EmptyDirectory) {
    auto empty_dir = test_dir / "empty";
    std::filesystem::create_directories(empty_dir);
    
    Scanner scanner(csv_path.string(), log_path.string(), 1);
    auto result = scanner.Scan(empty_dir);
    
    EXPECT_EQ(result.total_files, 0);
    EXPECT_EQ(result.malicious_files, 0);
    EXPECT_EQ(result.errors, 0);
}

TEST_F(ScannerTest, NonExistentScanDirectory) {
    Scanner scanner(csv_path.string(), log_path.string(), 1);
    
    EXPECT_THROW(
        scanner.Scan(test_dir / "nonexistent"),
        std::runtime_error
    );
}

TEST_F(ScannerTest, MultithreadedScan) {
    // Создаем больше файлов для тестирования многопоточности
    for (int i = 0; i < 10; ++i) {
        std::ofstream file(scan_dir / ("test_file_" + std::to_string(i) + ".txt"));
        file << "content " << i;
        file.close();
    }
    
    Scanner scanner(csv_path.string(), log_path.string(), 4);
    auto result = scanner.Scan(scan_dir);
    
    EXPECT_GT(result.total_files, 10); // Включая исходные тестовые файлы
    EXPECT_EQ(result.malicious_files, 1); // Только malware.exe
}

TEST_F(ScannerTest, LogFileCreation) {
    Scanner scanner(csv_path.string(), log_path.string(), 1);
    scanner.Scan(scan_dir);
    
    // Проверяем, что лог файл был создан и содержит данные
    EXPECT_TRUE(std::filesystem::exists(log_path));
    
    std::ifstream log_file(log_path);
    std::string log_content((std::istreambuf_iterator<char>(log_file)),
                            std::istreambuf_iterator<char>());
    
    EXPECT_FALSE(log_content.empty());
    EXPECT_TRUE(log_content.find("ВРЕДОНОСНЫЙ ФАЙЛ") != std::string::npos);
}

TEST_F(ScannerTest, CurrentStatsBeforeScan) {
    Scanner scanner(csv_path.string(), log_path.string(), 1);
    
    auto stats = scanner.GetCurrentStats();
    EXPECT_EQ(stats.total_files, 0);
    EXPECT_EQ(stats.malicious_files, 0);
    EXPECT_EQ(stats.errors, 0);
}
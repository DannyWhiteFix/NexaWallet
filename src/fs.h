// Copyright (c) 2017-2018 The Bitcoin Core developers
// Copyright (c) 2017-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_FS_H
#define NEXA_FS_H

#include <stdio.h>
#include <string>

#include <filesystem>
#include <fstream>
namespace fs = std::filesystem;

typedef std::fstream fstream;  // Because when we convert to std, it will be std::fstream
typedef std::ifstream fs_ifstream;  // Because when we convert to std, it will be std::fstream
typedef std::ofstream fs_ofstream;  // Because when we convert to std, it will be std::fstream

/** Bridge operations to C stdio */
namespace fsbridge {
    FILE *fopen(const fs::path& p, const char *mode);
    FILE *freopen(const fs::path& p, const char *mode, FILE *stream);
};

bool RenameOver(fs::path src, fs::path dest);

bool TryCreateDirectories(const fs::path &p);
fs::path GetDefaultDataDir();
const fs::path &GetDataDir(bool fNetSpecific = true);
void ClearDatadirCache();
fs::path GetConfigFile(const std::string &confPath);
#ifndef WIN32
fs::path GetPidFile();
void CreatePidFile(const fs::path &path, pid_t pid);
#endif

#ifdef WIN32
fs::path GetSpecialFolderPath(int nFolder, bool fCreate = true);
#endif

#endif

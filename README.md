# 📦 PortableXE Professional

> **Transform any Windows application into a portable, self-contained package**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)

## 🚀 Overview

PortableXE Professional is a comprehensive tool that converts Windows executables and installers into portable applications that can run from any location without installation. Perfect for creating USB-portable software, testing applications in isolated environments, or maintaining clean systems.

## ✨ Key Features

### 🔧 **Advanced Extraction Engine**
- **Multi-format Support**: 7-Zip, Inno Setup, MSI, NSIS, InstallShield, and more
- **Intelligent Detection**: Automatically identifies installer types and extraction methods
- **Fallback Mechanisms**: Multiple extraction strategies ensure maximum compatibility

### 🎯 **Smart Application Analysis**
- **PE Structure Analysis**: Deep inspection of executable architecture and subsystem
- **Installer Detection**: Recognizes setup files vs. standalone applications
- **Hash Verification**: SHA256 checksums for file integrity

### 📁 **Professional Portable Structure**
- **Standard Directory Layout**: App/, Data/, Documentation/, Plugins/
- **Environment Isolation**: Redirects AppData, Registry, and Temp folders
- **Multiple Launchers**: Batch, PowerShell, and conversion scripts included

### 🛠️ **Advanced Features**
- **System Dependencies**: Automatic Visual C++ Redistributable inclusion
- **Registry Backup**: Optional registry key preservation
- **Compression Options**: Configurable compression levels
- **Detailed Logging**: Comprehensive operation tracking

## 📋 System Requirements

- **Operating System**: Windows 10/11 (64-bit recommended)
- **Python**: 3.8 or higher
- **Memory**: 4GB RAM minimum, 8GB recommended
- **Storage**: 500MB for application + space for portable apps

### 🔗 **Optional Dependencies** (Recommended)
- **7-Zip**: For advanced archive extraction
- **innoextract**: For Inno Setup installer processing

## 🛠️ Installation

### Option 1: Python Installation
```bash
# Clone the repository
git clone https://github.com/LMLK-seal/portablexe.git
cd portablexe

# Install required packages
pip install customtkinter tkinter pathlib configparser

# Install optional dependencies for enhanced functionality
pip install pywin32
```

### Option 2: Portable Executable
Download the pre-compiled executable from the [Releases](https://github.com/LMLK-seal/portablexe/releases) page.

## 🎮 Quick Start

### 🖥️ **GUI Mode** (Recommended)
1. **Launch** PortableXE.py or the executable
2. **Select** your installer or executable file
3. **Configure** app name and output directory
4. **Click** "Create Portable App"
5. **Done!** Your portable app is ready

### 💻 **Command Line Usage** (Optional)
```bash
python PortableXE.py --input "installer.exe" --output "C:\PortableApps" --name "MyApp"
```

## 📁 Output Structure

```
MyApp_Portable/
├── 📁 App/                    # Core application files
│   ├── MyApp.exe
│   ├── Dependencies/          # System libraries
│   └── ...
├── 📁 Data/                   # Portable data storage
│   ├── AppData/              # Redirected AppData
│   ├── Registry/             # Registry backups
│   └── Profile/              # User profile data
├── 📁 Documentation/          # User documentation
├── 📁 Plugins/               # Application plugins
├── 🚀 RUN.bat                # Quick launcher
├── ⚙️ MyApp.bat              # Advanced launcher
├── 🔧 ConvertInstaller.bat   # Installer converter
└── 📄 README.md              # Usage instructions
```

## 🎯 Supported Formats

| Format | Support Level | Notes |
|--------|---------------|-------|
| **Inno Setup** | ✅ Excellent | Full extraction with innoextract |
| **NSIS** | ✅ Excellent | 7-Zip based extraction |
| **MSI** | ✅ Excellent | Native Windows Installer support |
| **InstallShield** | 🟨 Good | 7-Zip extraction |
| **WiX Toolset** | 🟨 Good | Standard MSI handling |
| **ZIP/RAR Archives** | ✅ Excellent | Native support |
| **Standalone EXE** | ✅ Perfect | Direct portable conversion |

## ⚙️ Configuration

PortableXE stores configuration in `%USERPROFILE%\PortableXE\config.ini`:

```ini
[General]
default_output_dir = C:\PortableApps
theme = dark
auto_analyze = true

[Advanced]
include_dependencies = true
create_launcher = true
compression_level = 6

[Extraction]
timeout_seconds = 300
use_7zip = true
use_innoextract = true
```

## 🔍 Troubleshooting

### 🐛 **Common Issues**

**Extraction Failed**
- Ensure 7-Zip and innoextract are installed and in PATH
- Try running as administrator for system-level installers
- Check installer isn't corrupted or password-protected

**Application Won't Start**
- Verify all dependencies are in the Dependencies folder
- Check Windows version compatibility
- Review creation logs for missing files

**Large File Sizes**
- Adjust compression level in settings
- Exclude unnecessary language packs or documentation
- Use selective extraction options

### 📞 **Getting Help**
1. Check the **Creation Log** tab for detailed error messages
2. Review generated **README.md** in the portable app folder
3. Enable detailed logging in configuration
4. Consult the **ConvertInstaller.bat** for manual conversion guidance


## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **7-Zip** project for archive extraction capabilities
- **innoextract** for Inno Setup installer support
- **CustomTkinter** for the modern GUI framework
- **Microsoft** for Windows Installer technology

---

<div align="center">

**Made with ❤️ by LMLK-seal**

[⭐ Star us on GitHub](https://github.com/LMLK-seal/portablexe) • [📝 Report Issues](https://github.com/LMLK-seal/portablexe/issues) • [💬 Discussions](https://github.com/LMLK-seal/portablexe/discussions)

</div>

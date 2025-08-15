"""
PortableXE - Professional Portable Application Creator
Version: 1.0.1
Author: PortableXE Development - LMLK-seal.
License: MIT

A professional-grade tool for converting Windows executables and installers
into portable applications that can run from any location without installation.
"""

import tkinter as tk
import customtkinter as ctk
from tkinter import filedialog, messagebox, ttk
import os
import shutil
import subprocess
import threading
import tempfile
import winreg
from pathlib import Path
import json
import zipfile
import time
import hashlib
import logging
from typing import List, Dict, Optional, Tuple
import struct
from datetime import datetime
import configparser

# Configure logging
def setup_logging():
    """Setup comprehensive logging system"""
    log_dir = os.path.join(os.path.expanduser("~"), "PortableXE", "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, f"portablexe_{datetime.now().strftime('%Y%m%d')}.log")
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(module)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

# --- Helper Functions for External Tools ---
def is_tool_in_path(name: str) -> bool:
    """Check whether `name` is on PATH and marked as executable."""
    return shutil.which(name) is not None

def find_7zip() -> Optional[str]:
    """Find 7z.exe in common locations or PATH."""
    seven_zip_paths = [
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
        os.path.join(os.environ.get('ProgramFiles', ''), '7-Zip', '7z.exe'),
        os.path.join(os.environ.get('ProgramFiles(x86)', ''), '7-Zip', '7z.exe')
    ]
    for path in seven_zip_paths:
        if os.path.exists(path):
            return path
    if is_tool_in_path("7z.exe"):
        return "7z.exe"
    return None

def find_innoextract() -> Optional[str]:
    """Find innoextract.exe in PATH."""
    if is_tool_in_path("innoextract.exe"):
        return "innoextract.exe"
    return None

class PortableXEConfig:
    """Configuration management for PortableXE"""
    
    def __init__(self):
        self.config_dir = os.path.join(os.path.expanduser("~"), "PortableXE")
        self.config_file = os.path.join(self.config_dir, "config.ini")
        self.config = configparser.ConfigParser()
        
        os.makedirs(self.config_dir, exist_ok=True)
        self.load_config()
    
    def load_config(self):
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            self.create_default_config()
    
    def create_default_config(self):
        """Create default configuration"""
        self.config['General'] = {
            'default_output_dir': os.path.join(os.path.expanduser("~"), "PortableApps"),
            'theme': 'dark',
            'auto_analyze': 'true',
            'create_logs': 'true'
        }
        
        self.config['Advanced'] = {
            'include_dependencies': 'true',
            'create_launcher': 'true',
            'backup_registry': 'false',
            'compression_level': '6',
            'max_temp_size_gb': '10'
        }
        
        self.config['Extraction'] = {
            'timeout_seconds': '300',
            'use_7zip': 'true',
            'use_innoextract': 'true',
            'use_msi_extract': 'true'
        }
        
        self.save_config()
    
    def save_config(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            self.config.write(f)
    
    def get(self, section: str, key: str, fallback: str = "") -> str:
        """Get configuration value"""
        return self.config.get(section, key, fallback=fallback)
    
    def set(self, section: str, key: str, value: str):
        """Set configuration value"""
        if not self.config.has_section(section):
            self.config.add_section(section)
        self.config.set(section, key, value)
        self.save_config()

class FileAnalyzer:
    """Advanced file analysis and type detection"""
    
    @staticmethod
    def get_file_hash(file_path: str) -> str:
        """Get SHA256 hash of file"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception:
            return ""
    
    @staticmethod
    def analyze_pe_structure(file_path: str) -> Dict:
        """Analyze PE (Portable Executable) structure"""
        analysis = {
            'is_valid_pe': False,
            'is_installer': False,
            'installer_type': 'unknown',
            'architecture': 'unknown',
            'subsystem': 'unknown',
            'sections': [],
            'imports': [],
            'resources': []
        }
        
        try:
            with open(file_path, 'rb') as f:
                # Read DOS header
                dos_header = f.read(64)
                if dos_header[:2] != b'MZ':
                    return analysis
                
                # Get PE header offset
                pe_offset = struct.unpack('<L', dos_header[60:64])[0]
                
                # Read PE signature
                f.seek(pe_offset)
                pe_sig = f.read(4)
                if pe_sig != b'PE\x00\x00':
                    return analysis
                
                analysis['is_valid_pe'] = True
                
                # Read COFF header
                coff_header = f.read(20)
                machine = struct.unpack('<H', coff_header[0:2])[0]
                num_sections = struct.unpack('<H', coff_header[2:4])[0]
                
                # Determine architecture
                if machine == 0x8664:
                    analysis['architecture'] = 'x64'
                elif machine == 0x14c:
                    analysis['architecture'] = 'x86'
                elif machine == 0x1c4:
                    analysis['architecture'] = 'ARM'
                
                # Read optional header
                opt_header_size = struct.unpack('<H', coff_header[16:18])[0]
                if opt_header_size > 0:
                    opt_header = f.read(opt_header_size)
                    if len(opt_header) >= 68:
                        subsystem = struct.unpack('<H', opt_header[68:70])[0]
                        if subsystem == 2:
                            analysis['subsystem'] = 'GUI'
                        elif subsystem == 3:
                            analysis['subsystem'] = 'Console'
                
                # Read section headers
                for i in range(num_sections):
                    section_header = f.read(40)
                    if len(section_header) == 40:
                        section_name = section_header[0:8].rstrip(b'\x00').decode('ascii', errors='ignore')
                        analysis['sections'].append(section_name)
                
        except Exception as e:
            logger.warning(f"PE analysis failed: {str(e)}")
        
        return analysis
    
    @staticmethod
    def detect_installer_type(file_path: str) -> Tuple[bool, str]:
        """Detect if file is an installer and its type"""
        try:
            filename = os.path.basename(file_path).lower()
            
            # Check filename patterns
            installer_patterns = [
                'setup', 'install', 'installer'
            ]
            
            for pattern in installer_patterns:
                if pattern in filename:
                    return True, "Generic Installer"
            
            # Check file content for installer signatures
            with open(file_path, 'rb') as f:
                data = f.read(8192)
                
                # Inno Setup
                if b'Inno Setup' in data or b'InnoSetup' in data:
                    return True, "Inno Setup"
                
                # NSIS
                if b'NSIS' in data or b'Nullsoft' in data or b'!insertmacro' in data:
                    return True, "NSIS"
                
                # InstallShield
                if b'InstallShield' in data:
                    return True, "InstallShield"
                
                # WiX Toolset
                if b'WiX' in data or b'Windows Installer' in data:
                    return True, "WiX"
                
                # Microsoft Installer
                if b'This installation package' in data:
                    return True, "Windows Installer"
                
                # Advanced Installer
                if b'Advanced Installer' in data:
                    return True, "Advanced Installer"
            
            # Check file size (large files often installers)
            file_size = os.path.getsize(file_path)
            if file_size > 50 * 1024 * 1024:  # > 50MB
                return True, "Large Executable (Likely Installer)"
            
            return False, "Standalone Application"
            
        except Exception as e:
            logger.error(f"Installer detection failed: {str(e)}")
            return False, "Unknown"

class ExtractionEngine:
    """Advanced extraction engine supporting multiple formats"""
    
    def __init__(self, config: PortableXEConfig):
        self.config = config
        self.temp_dir = None
        
    def extract_installer(self, installer_path: str, progress_callback=None) -> Optional[str]:
        """Extract installer using multiple methods"""
        self.temp_dir = tempfile.mkdtemp(prefix="portablexe_extract_")
        extract_dir = os.path.join(self.temp_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        
        logger.info(f"Starting extraction of: {installer_path}")
        
        try:
            # Method 1: 7-Zip extraction
            if self.config.get('Extraction', 'use_7zip') == 'true':
                if progress_callback:
                    progress_callback("Trying 7-Zip extraction...", 0.2)
                
                if self._extract_with_7zip(installer_path, extract_dir):
                    if self._validate_extraction(extract_dir):
                        logger.info("7-Zip extraction successful")
                        return extract_dir
                    else:
                        self._cleanup_failed_extraction(extract_dir)
            
            # Method 2: Inno Setup extraction
            if self.config.get('Extraction', 'use_innoextract') == 'true':
                if progress_callback:
                    progress_callback("Trying Inno Setup extraction...", 0.4)
                
                if self._extract_with_innoextract(installer_path, extract_dir):
                    if self._validate_extraction(extract_dir):
                        logger.info("Inno Setup extraction successful")
                        return extract_dir
                    else:
                        self._cleanup_failed_extraction(extract_dir)
            
            # Method 3: MSI extraction
            if installer_path.lower().endswith('.msi') and self.config.get('Extraction', 'use_msi_extract') == 'true':
                if progress_callback:
                    progress_callback("Trying MSI extraction...", 0.6)
                
                if self._extract_msi(installer_path, extract_dir):
                    if self._validate_extraction(extract_dir):
                        logger.info("MSI extraction successful")
                        return extract_dir
                    else:
                        self._cleanup_failed_extraction(extract_dir)
            
            # Method 4: Universal methods
            if progress_callback:
                progress_callback("Trying universal extraction methods...", 0.8)
            
            if self._extract_universal(installer_path, extract_dir):
                if self._validate_extraction(extract_dir):
                    logger.info("Universal extraction successful")
                    return extract_dir
            
            logger.warning("All extraction methods failed")
            return None
            
        except Exception as e:
            logger.error(f"Extraction failed: {str(e)}")
            return None
        
        finally:
            if progress_callback:
                progress_callback("Extraction completed", 1.0)
    
    def _extract_with_7zip(self, installer_path: str, extract_dir: str) -> bool:
        """Extract using 7-Zip"""
        try:
            seven_zip_exe = find_7zip()
            if not seven_zip_exe:
                logger.warning("7-Zip (7z.exe) not found. Skipping 7-Zip extraction.")
                return False
            
            cmd = [seven_zip_exe, "x", installer_path, f"-o{extract_dir}", "-y", "-bb1"]
            
            timeout = int(self.config.get('Extraction', 'timeout_seconds', '300'))
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, creationflags=subprocess.CREATE_NO_WINDOW)
            
            return result.returncode == 0 and len(os.listdir(extract_dir)) > 0
            
        except Exception as e:
            logger.warning(f"7-Zip extraction failed: {str(e)}")
            return False
    
    def _extract_with_innoextract(self, installer_path: str, extract_dir: str) -> bool:
        """Extract using innoextract"""
        try:
            innoextract_exe = find_innoextract()
            if not innoextract_exe:
                logger.warning("innoextract not found. Skipping Inno Setup extraction.")
                return False
                
            cmd = [innoextract_exe, installer_path, "-d", extract_dir, "-s"]
            
            timeout = int(self.config.get('Extraction', 'timeout_seconds', '300'))
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, creationflags=subprocess.CREATE_NO_WINDOW)
            
            return result.returncode == 0 and len(os.listdir(extract_dir)) > 0
            
        except Exception as e:
            logger.warning(f"Innoextract failed: {str(e)}")
            return False
    
    def _extract_msi(self, installer_path: str, extract_dir: str) -> bool:
        """Extract MSI files"""
        try:
            cmd = ["msiexec", "/a", installer_path, "/qb", f"TARGETDIR={extract_dir}"]
            
            timeout = int(self.config.get('Extraction', 'timeout_seconds', '300'))
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, creationflags=subprocess.CREATE_NO_WINDOW)
            
            return result.returncode == 0 and len(os.listdir(extract_dir)) > 0
            
        except Exception as e:
            logger.warning(f"MSI extraction failed: {str(e)}")
            return False
    
    def _extract_universal(self, installer_path: str, extract_dir: str) -> bool:
        """Universal extraction methods"""
        try:
            # Try ZIP extraction
            try:
                with zipfile.ZipFile(installer_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                if len(os.listdir(extract_dir)) > 0:
                    return True
            except:
                pass
            
            return False
            
        except Exception:
            return False
    
    def _validate_extraction(self, extract_dir: str) -> bool:
        """Validate that extraction was successful"""
        if not extract_dir or not os.path.exists(extract_dir):
            return False
        
        files = os.listdir(extract_dir)
        if len(files) == 0:
            return False
        
        # Check for PE file sections (indicates failed extraction)
        pe_sections = ['.text', '.data', '.rdata', '.bss', '.idata', '.edata', '.rsrc']
        pe_section_count = sum(1 for f in files if any(f.startswith(section) for section in pe_sections))
        
        # If more than 3 PE sections found, likely a failed extraction
        if pe_section_count > 3:
            logger.warning("Extraction appears to have dissected PE file structure")
            return False
        
        # Check for actual executable files or meaningful content
        exe_count = 0
        meaningful_files = 0
        
        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                if file.lower().endswith(('.exe', '.dll', '.sys')):
                    exe_count += 1
                if file.lower().endswith(('.exe', '.dll', '.txt', '.ini', '.cfg', '.dat')):
                    meaningful_files += 1
        
        return exe_count > 0 or meaningful_files > 5
    
    def _cleanup_failed_extraction(self, extract_dir: str):
        """Clean up failed extraction attempts"""
        try:
            if os.path.exists(extract_dir):
                shutil.rmtree(extract_dir)
                os.makedirs(extract_dir, exist_ok=True)
        except Exception:
            pass
    
    def cleanup(self):
        """Clean up temporary files"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
                logger.info(f"Cleaned up temp directory: {self.temp_dir}")
            except Exception as e:
                logger.warning(f"Cleanup failed: {str(e)}")

class PortableAppBuilder:
    """Build portable applications with advanced features"""
    
    def __init__(self, config: PortableXEConfig):
        self.config = config
        
    def build_portable_app(self, source_path: str, output_dir: str, app_name: str, 
                          is_standalone: bool = False, progress_callback=None) -> str:
        """Build portable application"""
        
        portable_dir = os.path.join(output_dir, f"{app_name}_Portable")
        logger.info(f"Building portable app: {portable_dir}")
        
        try:
            # Create directory structure
            if progress_callback:
                progress_callback("Creating directory structure...", 0.1)
            
            self._create_directory_structure(portable_dir)
            
            # Copy application files
            if progress_callback:
                progress_callback("Copying application files...", 0.3)
            
            app_dir = os.path.join(portable_dir, "App")
            if is_standalone:
                # Copy single executable
                shutil.copy2(source_path, app_dir)
            else:
                # Copy extracted directory
                if os.path.isdir(source_path):
                    self._copy_directory_contents(source_path, app_dir)
                else:
                    shutil.copy2(source_path, app_dir)
            
            # Copy system dependencies
            if self.config.get('Advanced', 'include_dependencies') == 'true':
                if progress_callback:
                    progress_callback("Including system dependencies...", 0.5)
                
                self._copy_system_dependencies(app_dir)
            
            # Create portable launcher
            if self.config.get('Advanced', 'create_launcher') == 'true':
                if progress_callback:
                    progress_callback("Creating portable launcher...", 0.7)
                
                self._create_advanced_launcher(portable_dir, app_name)
            
            # Create configuration files
            if progress_callback:
                progress_callback("Creating configuration files...", 0.9)
            
            self._create_config_files(portable_dir, app_name, is_standalone)
            
            if progress_callback:
                progress_callback("Portable app created successfully!", 1.0)
            
            logger.info(f"Portable app created: {portable_dir}")
            return portable_dir
            
        except Exception as e:
            logger.error(f"Failed to build portable app: {str(e)}")
            raise
    
    def _create_directory_structure(self, portable_dir: str):
        """Create standard portable app directory structure"""
        directories = [
            portable_dir,
            os.path.join(portable_dir, "App"),
            os.path.join(portable_dir, "Data"),
            os.path.join(portable_dir, "Data", "AppData"),
            os.path.join(portable_dir, "Data", "LocalAppData"),
            os.path.join(portable_dir, "Data", "Profile"),
            os.path.join(portable_dir, "Data", "Registry"),
            os.path.join(portable_dir, "Data", "Temp"),
            os.path.join(portable_dir, "Data", "Settings"),
            os.path.join(portable_dir, "Documentation"),
            os.path.join(portable_dir, "Plugins")
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    def _copy_directory_contents(self, source: str, destination: str):
        """Copy directory contents with progress"""
        try:
            for item in os.listdir(source):
                src_path = os.path.join(source, item)
                dst_path = os.path.join(destination, item)
                
                if os.path.isdir(src_path):
                    shutil.copytree(src_path, dst_path, dirs_exist_ok=True)
                else:
                    shutil.copy2(src_path, dst_path)
        except Exception as e:
            logger.error(f"Failed to copy directory contents: {str(e)}")
            raise
    
    def _copy_system_dependencies(self, app_dir: str):
        """Copy system dependencies"""
        try:
            system32_dir = os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'System32')
            
            # Visual C++ Redistributables
            vc_redist_dlls = [
                # Visual Studio 2015-2022
                'msvcp140.dll', 'vcruntime140.dll', 'concrt140.dll', 'vccorlib140.dll',
                'vcruntime140_1.dll', 'msvcp140_1.dll', 'msvcp140_2.dll',
                
                # Visual Studio 2013
                'msvcp120.dll', 'msvcr120.dll', 'vccorlib120.dll',
                
                # Visual Studio 2012
                'msvcp110.dll', 'msvcr110.dll', 'vccorlib110.dll',
                
                # Visual Studio 2010
                'msvcp100.dll', 'msvcr100.dll',
                
                # Visual Studio 2008
                'msvcp90.dll', 'msvcr90.dll',
                
                # Common system libraries
                'mfc140.dll', 'mfc140u.dll', 'mfcm140.dll', 'mfcm140u.dll'
            ]
            
            deps_dir = os.path.join(app_dir, "Dependencies")
            os.makedirs(deps_dir, exist_ok=True)
            
            copied_count = 0
            for dll in vc_redist_dlls:
                src_path = os.path.join(system32_dir, dll)
                if os.path.exists(src_path):
                    try:
                        dst_path = os.path.join(deps_dir, dll)
                        shutil.copy2(src_path, dst_path)
                        copied_count += 1
                    except Exception:
                        pass  # Skip if can't copy (permission issues)
            
            logger.info(f"Copied {copied_count} system dependencies")
            
        except Exception as e:
            logger.warning(f"Failed to copy system dependencies: {str(e)}")
    
    def _create_advanced_launcher(self, portable_dir: str, app_name: str):
        """Create advanced portable launcher"""
        
        # Create main launcher
        main_launcher = self._generate_main_launcher(portable_dir, app_name)
        launcher_path = os.path.join(portable_dir, f"{app_name}.bat")
        
        with open(launcher_path, 'w', encoding='utf-8') as f:
            f.write(main_launcher)
        
        # Create simple RUN launcher
        run_launcher = f'''@echo off
echo Starting {app_name}...
call "%~dp0{app_name}.bat"
'''
        
        run_path = os.path.join(portable_dir, "RUN.bat")
        with open(run_path, 'w', encoding='utf-8') as f:
            f.write(run_launcher)
        
        # Create PowerShell launcher
        ps_launcher = self._generate_powershell_launcher(portable_dir, app_name)
        ps_path = os.path.join(portable_dir, f"{app_name}.ps1")
        
        with open(ps_path, 'w', encoding='utf-8') as f:
            f.write(ps_launcher)
        
        # Create installer converter script
        converter_script = self._generate_installer_converter(portable_dir, app_name)
        converter_path = os.path.join(portable_dir, "ConvertInstaller.bat")
        
        with open(converter_path, 'w', encoding='utf-8') as f:
            f.write(converter_script)
    
    def _generate_main_launcher(self, portable_dir: str, app_name: str) -> str:
        """Generate main launcher script"""
        return f'''@echo off
setlocal EnableDelayedExpansion

:: PortableXE Launcher for {app_name}
:: Generated by PortableXE Professional v1.0.0
title {app_name} - Portable Launcher

echo ================================================
echo {app_name} - Portable Application
echo ================================================
echo.

:: Get directories
set "PORTABLE_DIR=%~dp0"
set "APP_DIR=%PORTABLE_DIR%App"
set "DATA_DIR=%PORTABLE_DIR%Data"
set "PLUGINS_DIR=%PORTABLE_DIR%Plugins"

:: Check if this is first run
if not exist "%DATA_DIR%\\first_run_complete" (
    echo First run detected. Initializing portable environment...
    call :initialize_portable_env
)

:: Set portable environment variables
echo Setting up portable environment...
set "APPDATA=%DATA_DIR%\\AppData"
set "LOCALAPPDATA=%DATA_DIR%\\LocalAppData"
set "USERPROFILE=%DATA_DIR%\\Profile"
set "TEMP=%DATA_DIR%\\Temp"
set "TMP=%DATA_DIR%\\Temp"
set "HOME=%DATA_DIR%\\Profile"
set "HOMEPATH=%DATA_DIR%\\Profile"
set "HOMEDRIVE=C:"

:: Create directories if they don't exist
for %%d in ("%APPDATA%" "%LOCALAPPDATA%" "%USERPROFILE%" "%TEMP%") do (
    if not exist %%d (
        echo Creating: %%d
        mkdir %%d
    )
)

:: Add app directories to PATH
if exist "%APP_DIR%\\Dependencies" (
    set "PATH=%APP_DIR%\\Dependencies;%APP_DIR%;%PLUGINS_DIR%;%PATH%"
) else (
    set "PATH=%APP_DIR%;%PLUGINS_DIR%;%PATH%"
)

:: Set additional portable variables
set "PORTABLE=1"
set "PORTABLEAPPS_DIR=%PORTABLE_DIR%"

:: Find and launch main executable
echo Searching for main executable...
call :find_and_launch_exe

goto :end

:initialize_portable_env
echo Initializing portable environment...

:: Create registry backup if requested
if exist "%APP_DIR%\\backup_registry.flag" (
    echo Backing up relevant registry keys...
    call :backup_registry
)

:: Mark first run as complete
echo. > "%DATA_DIR%\\first_run_complete"
echo Initialization complete.
echo.
return

:find_and_launch_exe
set "FOUND_EXE="
set "EXE_COUNT=0"

:: Look for main executable patterns
for %%p in ("{app_name}.exe" "main.exe" "app.exe" "start.exe") do (
    if exist "%APP_DIR%\\%%~p" (
        set "FOUND_EXE=%APP_DIR%\\%%~p"
        goto :launch_found_exe
    )
)

:: Search for any suitable executable
for /r "%APP_DIR%" %%f in (*.exe) do (
    set "filename=%%~nf"
    set "filesize=%%~zf"
    set /a EXE_COUNT+=1
    
    :: Skip known system/installer files
    echo !filename! | findstr /i "unins setup install update crash error report vcredist directx" >nul
    if !errorlevel! neq 0 (
        :: Prefer smaller executables (less likely to be installers)
        if !filesize! LSS 100000000 (
            if not defined FOUND_EXE (
                set "FOUND_EXE=%%f"
            )
        )
    )
)

:launch_found_exe
if defined FOUND_EXE (
    echo Found executable: !FOUND_EXE!
    echo Launching application...
    echo.
    
    :: Change to app directory for relative paths
    pushd "%APP_DIR%"
    
    :: Launch with error handling
    start "" "!FOUND_EXE!" %*
    
    if !errorlevel! equ 0 (
        echo Application launched successfully!
        echo Data location: %DATA_DIR%
    ) else (
        echo Warning: Application may not have started correctly.
    )
    
    popd
) else (
    echo No suitable executable found.
    echo.
    echo Available executables:
    for /r "%APP_DIR%" %%f in (*.exe) do echo   %%f
    echo.
    echo Please run the desired executable manually.
    pause
)
return

:backup_registry
:: Create registry backup for common application keys
set "REG_BACKUP=%DATA_DIR%\\Registry\\backup.reg"
mkdir "%DATA_DIR%\\Registry" 2>nul

echo Backing up registry keys...
reg export "HKCU\\Software\\{app_name}" "%REG_BACKUP%" /y 2>nul
reg export "HKLM\\Software\\{app_name}" "%REG_BACKUP%.machine" /y 2>nul
return

:end
endlocal
'''
    
    def _generate_powershell_launcher(self, portable_dir: str, app_name: str) -> str:
        """Generate PowerShell launcher"""
        return f'''# PortableXE PowerShell Launcher for {app_name}
# Generated by PortableXE Professional v1.0.0

param(
    [string[]]$Arguments = @()
)

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "{app_name} - Portable Application" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Get directories
$PortableDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AppDir = Join-Path $PortableDir "App"
$DataDir = Join-Path $PortableDir "Data"

# Set portable environment variables
$env:APPDATA = Join-Path $DataDir "AppData"
$env:LOCALAPPDATA = Join-Path $DataDir "LocalAppData"
$env:USERPROFILE = Join-Path $DataDir "Profile"
$env:TEMP = Join-Path $DataDir "Temp"
$env:TMP = Join-Path $DataDir "Temp"
$env:PORTABLE = "1"

# Create directories if they don't exist
@($env:APPDATA, $env:LOCALAPPDATA, $env:USERPROFILE, $env:TEMP) | ForEach-Object {{
    if (!(Test-Path $_)) {{
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
        Write-Host "Created: $_" -ForegroundColor Green
    }}
}}

# Add app directory to PATH
$DepsDir = Join-Path $AppDir "Dependencies"
if (Test-Path $DepsDir) {{
    $env:PATH = "$DepsDir;$AppDir;$($env:PATH)"
}} else {{
    $env:PATH = "$AppDir;$($env:PATH)"
}}

# Find and launch executable
Write-Host "Searching for main executable..." -ForegroundColor Yellow

$MainExe = $null
$ExeCandidates = @(
    "{app_name}.exe",
    "main.exe", 
    "app.exe",
    "start.exe"
)

# Look for preferred executable names
foreach ($candidate in $ExeCandidates) {{
    $ExePath = Join-Path $AppDir $candidate
    if (Test-Path $ExePath) {{
        $MainExe = $ExePath
        break
    }}
}}

# If not found, search for any suitable executable
if (-not $MainExe) {{
    $AllExes = Get-ChildItem -Path $AppDir -Filter "*.exe" -Recurse | Where-Object {{
        $_.Name -notmatch "unins|setup|install|update|crash|error|report"
    }}
    
    if ($AllExes) {{
        $MainExe = $AllExes[0].FullName
    }}
}}

if ($MainExe) {{
    Write-Host "Found executable: $MainExe" -ForegroundColor Green
    Write-Host "Launching application..." -ForegroundColor Yellow
    
    Set-Location $AppDir
    Start-Process -FilePath $MainExe -ArgumentList $Arguments -WorkingDirectory $AppDir
    
    Write-Host "Application launched successfully!" -ForegroundColor Green
    Write-Host "Data location: $DataDir" -ForegroundColor Cyan
}} else {{
    Write-Host "No suitable executable found!" -ForegroundColor Red
    Write-Host "Available executables:" -ForegroundColor Yellow
    Get-ChildItem -Path $AppDir -Filter "*.exe" -Recurse | ForEach-Object {{
        Write-Host "  $($_.FullName)" -ForegroundColor Gray
    }}
}}
'''
    
    def _generate_installer_converter(self, portable_dir: str, app_name: str) -> str:
        """Generate installer converter script"""
        return f'''@echo off
setlocal EnableDelayedExpansion

:: PortableXE Installer Converter for {app_name}
:: This script helps convert installers to portable applications

title {app_name} - Installer Converter

echo ================================================
echo {app_name} - Installer to Portable Converter
echo ================================================
echo.
echo This tool helps convert installers to portable apps
echo by temporarily installing and extracting files.
echo.

set "PORTABLE_DIR=%~dp0"
set "APP_DIR=%PORTABLE_DIR%App"
set "DATA_DIR=%PORTABLE_DIR%Data"
set "TEMP_INSTALL=%TEMP%\\PortableXE_TempInstall_%RANDOM%"

echo Current portable directory: %PORTABLE_DIR%
echo.

:: Check if we already have proper executables
echo Analyzing current App directory...
call :analyze_current_app

echo.
echo CONVERSION OPTIONS:
echo 1. Auto-convert installer to portable app
echo 2. Manual installation guidance
echo 3. Skip conversion and try current files
echo 4. Exit
echo.

choice /C 1234 /M "Choose option"
set "user_choice=!errorlevel!"

if !user_choice! equ 1 goto :auto_convert
if !user_choice! equ 2 goto :manual_guidance
if !user_choice! equ 3 goto :try_current
if !user_choice! equ 4 goto :end

:auto_convert
echo.
echo ========================================
echo AUTO-CONVERSION MODE
echo ========================================
echo.
echo This will attempt to:
echo 1. Temporarily install the application
echo 2. Extract the installed files
echo 3. Copy them to your portable app
echo 4. Clean up the temporary installation
echo.

choice /C YN /M "Continue with auto-conversion?"
if !errorlevel! equ 2 goto :end

:: Find installer
set "INSTALLER="
set "INSTALLER_SIZE=0"

for %%f in ("%APP_DIR%\\*.exe") do (
    set "filesize=%%~zf"
    if !filesize! GTR 1000000 (
        set "INSTALLER=%%f"
        set "INSTALLER_SIZE=!filesize!"
    )
)

if not defined INSTALLER (
    echo ERROR: No installer executable found in App directory
    pause
    goto :end
)

echo Found installer: %INSTALLER%
echo Size: %INSTALLER_SIZE% bytes
echo.

:: Create backup of current App directory
if exist "%APP_DIR%_backup" rmdir /s /q "%APP_DIR%_backup"
echo Creating backup of current App directory...
xcopy "%APP_DIR%" "%APP_DIR%_backup\\" /E /I /H /Y >nul

:: Attempt silent installation
echo Attempting silent installation...
mkdir "%TEMP_INSTALL%" 2>nul

:: Try common silent install parameters
echo Trying /S /D=%TEMP_INSTALL%...
"%INSTALLER%" /S /D=%TEMP_INSTALL%
if !errorlevel! equ 0 goto :check_installation

echo Trying /SILENT /DIR="%TEMP_INSTALL%"...
"%INSTALLER%" /SILENT /DIR="%TEMP_INSTALL%"
if !errorlevel! equ 0 goto :check_installation

echo Trying --silent --install-dir="%TEMP_INSTALL%"...
"%INSTALLER%" --silent --install-dir="%TEMP_INSTALL%"
if !errorlevel! equ 0 goto :check_installation

echo Silent installation failed. Launching manual installation...
echo.
echo MANUAL INSTALLATION INSTRUCTIONS:
echo 1. Choose "Custom" or "Advanced" installation
echo 2. Set installation directory to: %TEMP_INSTALL%
echo 3. Complete the installation
echo 4. Return here and press any key
echo.
echo Installation directory: %TEMP_INSTALL%
pause

start "" "%INSTALLER%"
echo Waiting for manual installation to complete...
pause

:check_installation
echo.
echo Checking installation results...

:: Check temporary install directory
if exist "%TEMP_INSTALL%" (
    echo Found temporary installation at: %TEMP_INSTALL%
    goto :copy_installed_files
)

:: Check common installation paths
set "FOUND_INSTALL="
for %%p in ("C:\\Program Files\\{app_name}" "C:\\Program Files (x86)\\{app_name}" "%LOCALAPPDATA%\\Programs\\{app_name}" "%PROGRAMFILES%\\{app_name}") do (
    if exist %%p (
        echo Found installation at: %%p
        set "FOUND_INSTALL=%%p"
        goto :copy_installed_files
    )
)

echo ERROR: Could not locate installed files
echo Please check if installation completed successfully
pause
goto :restore_backup

:copy_installed_files
if defined FOUND_INSTALL set "TEMP_INSTALL=%FOUND_INSTALL%"

echo.
echo Copying installed files to portable app...

:: Clear current App directory
rmdir /s /q "%APP_DIR%"
mkdir "%APP_DIR%"

:: Copy all files from installation
echo Copying from: %TEMP_INSTALL%
echo To: %APP_DIR%
xcopy "%TEMP_INSTALL%\\*" "%APP_DIR%\\" /E /I /H /Y /C

:: Check if copy was successful
if exist "%APP_DIR%\\*.exe" (
    echo Files copied successfully!
    call :cleanup_temp_install
    goto :conversion_complete
) else (
    echo ERROR: File copy failed or no executables found
    goto :restore_backup
)

:cleanup_temp_install
echo Cleaning up temporary installation...
if exist "%TEMP_INSTALL%" (
    rmdir /s /q "%TEMP_INSTALL%" 2>nul
)

:: Try to uninstall if registry entries exist
echo Checking for uninstaller...
for /f "tokens=*" %%a in ('reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall" /s /f "{app_name}" 2^>nul') do (
    echo Found registry entry: %%a
    :: Could attempt automatic uninstall here
)
return

:conversion_complete
echo.
echo ========================================
echo CONVERSION COMPLETED SUCCESSFULLY!
echo ========================================
echo.
echo The installer has been converted to a portable application.
echo Original files backed up to: %APP_DIR%_backup
echo.
echo Testing the portable application...
call :test_portable_app
goto :end

:restore_backup
echo.
echo Restoring backup due to conversion failure...
if exist "%APP_DIR%_backup" (
    rmdir /s /q "%APP_DIR%"
    move "%APP_DIR%_backup" "%APP_DIR%"
    echo Backup restored successfully.
) else (
    echo WARNING: No backup found to restore!
)
goto :end

:manual_guidance
echo.
echo ========================================
echo MANUAL CONVERSION GUIDANCE
echo ========================================
echo.
echo To manually convert this installer:
echo.
echo 1. Install {app_name} normally on your system
echo 2. Locate the installation directory (usually in Program Files)
echo 3. Copy ALL files from the installation directory
echo 4. Paste them into: %APP_DIR%
echo 5. Replace the installer with the actual program files
echo 6. Run this converter again to test
echo.
echo Common installation locations:
echo - C:\\Program Files\\{app_name}
echo - C:\\Program Files (x86)\\{app_name}
echo - %%LOCALAPPDATA%%\\Programs\\{app_name}
echo.
pause
goto :end

:try_current
echo.
echo Testing current files...
call :test_portable_app
goto :end

:analyze_current_app
set "EXE_COUNT=0"
set "LARGE_FILES=0"
set "TOTAL_SIZE=0"

for /r "%APP_DIR%" %%f in (*) do (
    set "filesize=%%~zf"
    set /a TOTAL_SIZE+=!filesize!
    
    if "%%~xf"==".exe" (
        set /a EXE_COUNT+=1
        if !filesize! GTR 50000000 (
            set /a LARGE_FILES+=1
            echo Large executable found: %%f (!filesize! bytes^)
        ) else (
            echo Executable found: %%f (!filesize! bytes^)
        )
    )
)

echo Analysis complete:
echo - Total executables: %EXE_COUNT%
echo - Large files (^>50MB^): %LARGE_FILES%
echo - Total size: %TOTAL_SIZE% bytes

if %LARGE_FILES% GTR 0 (
    echo.
    echo WARNING: Large executables detected - likely installers
    echo Conversion recommended for proper portable operation
)
return

:test_portable_app
echo.
echo Testing portable application...

:: Look for main executable
set "TEST_EXE="
for %%f in ("%APP_DIR%\\{app_name}.exe" "%APP_DIR%\\main.exe") do (
    if exist %%f (
        set "TEST_EXE=%%f"
        goto :found_test_exe
    )
)

:: Find any suitable executable
for /r "%APP_DIR%" %%f in (*.exe) do (
    set "filename=%%~nf"
    echo !filename! | findstr /i "unins setup install" >nul
    if !errorlevel! neq 0 (
        set "TEST_EXE=%%f"
        goto :found_test_exe
    )
)

:found_test_exe
if defined TEST_EXE (
    echo Found test executable: !TEST_EXE!
    choice /C YN /M "Launch test executable now?"
    if !errorlevel! equ 1 (
        echo Launching: !TEST_EXE!
        start "" "!TEST_EXE!"
        echo Test launch completed.
    )
) else (
    echo No suitable executable found for testing.
    echo Available files:
    dir "%APP_DIR%\\*.exe" /b 2>nul
)
return

:end
echo.
echo Converter finished.
pause
endlocal
'''
    
    def _create_config_files(self, portable_dir: str, app_name: str, is_standalone: bool):
        """Create comprehensive configuration files"""
        
        # Create portable app configuration
        config_data = {
            "app_info": {
                "name": app_name,
                "version": "1.0.0",
                "type": "standalone" if is_standalone else "extracted_installer",
                "created_date": datetime.now().isoformat(),
                "created_by": "PortableXE Professional v1.0.0"
            },
            "portable_settings": {
                "data_directory": "./Data",
                "redirect_appdata": True,
                "redirect_registry": False,
                "isolated_temp": True,
                "preserve_permissions": True
            },
            "launcher_settings": {
                "auto_detect_exe": True,
                "backup_registry": False,
                "create_desktop_shortcut": False,
                "cleanup_on_exit": False
            }
        }
        
        config_path = os.path.join(portable_dir, "portable_config.json")
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, indent=2, ensure_ascii=False)
        
        # Create comprehensive README
        readme_content = self._generate_readme(app_name, is_standalone)
        readme_path = os.path.join(portable_dir, "README.md")
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(readme_content)
        
        # Create simple info file
        info_content = f'''Application: {app_name}
Type: {"Standalone Application" if is_standalone else "Extracted Installer"}
Portable: Yes
Created: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Creator: PortableXE Professional v1.0.0

Quick Start:
1. Double-click RUN.bat to start
2. Or run {app_name}.bat for detailed startup
3. All data stored in Data/ folder

Support: Visit PortableXE documentation for help
'''
        
        info_path = os.path.join(portable_dir, "INFO.txt")
        with open(info_path, 'w', encoding='utf-8') as f:
            f.write(info_content)
    
    def _generate_readme(self, app_name: str, is_standalone: bool) -> str:
        """Generate comprehensive README"""
        return f'''# {app_name} - Portable Version

Generated by **PortableXE Professional v1.0.0**

This is a portable version of **{app_name}**. It can be run from any location, including USB drives, without installation.

## How to Use

1.  **Launch**: Double-click on `RUN.bat` or `{app_name}.bat` to start the application.
    *   `RUN.bat`: A simple launcher.
    *   `{app_name}.bat`: A more advanced launcher with a console window showing status messages.
    *   `{app_name}.ps1`: A PowerShell equivalent of the advanced launcher.

2.  **Data Storage**: All application data, settings, and user profiles are stored inside the `Data` folder. This keeps your host system clean.

3.  **Updating**: To update the application, replace the contents of the `App` folder with the new version's files. Your data in the `Data` folder will be preserved.

## Directory Structure

-   `/App`: Contains the core application files.
-   `/Data`: Stores all user data, settings, and registry modifications.
-   `/Documentation`: Place for any user documentation.
-   `/Plugins`: Directory for application plugins.
-   `RUN.bat`: The main launcher script.

## Notes

-   This application's environment is self-contained. It redirects common folders like `AppData` and `Temp` to the `Data` directory.
-   If the application seems to be an installer, you can use `ConvertInstaller.bat` to guide you through extracting the actual application files.

Thank you for using PortableXE!
'''

class PortableXE_GUI(ctk.CTk):
    """The main GUI for the PortableXE application."""
    
    def __init__(self):
        super().__init__()
        
        self.title("PortableXE - Professional Portable Application Creator")
        self.geometry("800x650")
        
        self.config = PortableXEConfig()
        
        # --- Configure Grid Layout ---
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)
        
        # --- UI Components ---
        self._create_widgets()
        self.check_dependencies()
        
    def _create_widgets(self):
        """Create and arrange all GUI widgets."""
        
        # --- Input File Frame ---
        input_frame = ctk.CTkFrame(self)
        input_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        input_frame.grid_columnconfigure(1, weight=1)
        
        ctk.CTkLabel(input_frame, text="Input File:").grid(row=0, column=0, padx=10, pady=10)
        self.input_file_entry = ctk.CTkEntry(input_frame, placeholder_text="Select an executable or installer...")
        self.input_file_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        ctk.CTkButton(input_frame, text="Browse...", command=self.select_input_file).grid(row=0, column=2, padx=10, pady=10)
        
        # --- Options Frame ---
        options_frame = ctk.CTkFrame(self)
        options_frame.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="ew")
        options_frame.grid_columnconfigure(1, weight=1)
        
        ctk.CTkLabel(options_frame, text="App Name:").grid(row=0, column=0, padx=10, pady=10)
        self.app_name_entry = ctk.CTkEntry(options_frame, placeholder_text="e.g., MyApp")
        self.app_name_entry.grid(row=0, column=1, columnspan=2, padx=10, pady=10, sticky="ew")
        
        ctk.CTkLabel(options_frame, text="Output Dir:").grid(row=1, column=0, padx=10, pady=10)
        self.output_dir_entry = ctk.CTkEntry(options_frame)
        self.output_dir_entry.insert(0, self.config.get('General', 'default_output_dir'))
        self.output_dir_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
        ctk.CTkButton(options_frame, text="Browse...", command=self.select_output_dir).grid(row=1, column=2, padx=10, pady=10)
        
        # --- Analysis and Log Tabs ---
        tab_view = ctk.CTkTabview(self)
        tab_view.grid(row=2, column=0, rowspan=2, padx=10, pady=10, sticky="nsew")
        tab_view.add("File Analysis")
        tab_view.add("Creation Log")
        
        self.analysis_textbox = ctk.CTkTextbox(tab_view.tab("File Analysis"), wrap="word", state="disabled")
        self.analysis_textbox.pack(expand=True, fill="both", padx=5, pady=5)
        
        self.log_textbox = ctk.CTkTextbox(tab_view.tab("Creation Log"), wrap="word", state="disabled")
        self.log_textbox.pack(expand=True, fill="both", padx=5, pady=5)
        
        # --- Progress and Action Frame ---
        progress_frame = ctk.CTkFrame(self)
        progress_frame.grid(row=4, column=0, padx=10, pady=10, sticky="ew")
        progress_frame.grid_columnconfigure(0, weight=1)
        
        self.progress_label = ctk.CTkLabel(progress_frame, text="Ready")
        self.progress_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        
        self.progress_bar = ctk.CTkProgressBar(progress_frame)
        self.progress_bar.set(0)
        self.progress_bar.grid(row=1, column=0, columnspan=2, padx=10, pady=(0, 10), sticky="ew")
        
        self.create_button = ctk.CTkButton(progress_frame, text="Create Portable App", command=self.create_portable_app, height=35)
        self.create_button.grid(row=0, column=1, rowspan=2, padx=10, pady=10, sticky="e")
    
    def select_input_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Executable or Installer",
            filetypes=(("Executable Files", "*.exe"), ("MSI Packages", "*.msi"), ("All Files", "*.*"))
        )
        if file_path:
            self.input_file_entry.delete(0, "end")
            self.input_file_entry.insert(0, file_path)
            
            # Auto-fill app name
            app_name = Path(file_path).stem
            # Clean common installer names
            for term in ['setup', 'install', 'installer']:
                app_name = app_name.lower().replace(term, '')
            app_name = app_name.strip(' _-').capitalize()
            self.app_name_entry.delete(0, "end")
            self.app_name_entry.insert(0, app_name)
            
            if self.config.get('General', 'auto_analyze') == 'true':
                self.analyze_file(file_path)

    def select_output_dir(self):
        dir_path = filedialog.askdirectory(title="Select Output Directory")
        if dir_path:
            self.output_dir_entry.delete(0, "end")
            self.output_dir_entry.insert(0, dir_path)

    def analyze_file(self, file_path):
        self.analysis_textbox.configure(state="normal")
        self.analysis_textbox.delete("1.0", "end")
        
        try:
            self.analysis_textbox.insert("end", f"Analyzing: {os.path.basename(file_path)}\n\n")
            
            file_size = os.path.getsize(file_path) / (1024 * 1024)
            self.analysis_textbox.insert("end", f"File Size: {file_size:.2f} MB\n")
            
            file_hash = FileAnalyzer.get_file_hash(file_path)
            self.analysis_textbox.insert("end", f"SHA256 Hash: {file_hash}\n\n")
            
            is_installer, installer_type = FileAnalyzer.detect_installer_type(file_path)
            self.analysis_textbox.insert("end", f"Detected Type: {installer_type}\n")
            self.analysis_textbox.insert("end", f"Is Installer: {'Yes' if is_installer else 'No'}\n\n")
            
            pe_info = FileAnalyzer.analyze_pe_structure(file_path)
            if pe_info['is_valid_pe']:
                self.analysis_textbox.insert("end", "PE Structure Analysis:\n")
                self.analysis_textbox.insert("end", f"  - Architecture: {pe_info['architecture']}\n")
                self.analysis_textbox.insert("end", f"  - Subsystem: {pe_info['subsystem']}\n")
            else:
                self.analysis_textbox.insert("end", "Not a valid PE file.\n")
                
        except Exception as e:
            self.analysis_textbox.insert("end", f"Analysis failed: {str(e)}")
        finally:
            self.analysis_textbox.configure(state="disabled")

    def log_message(self, message: str, level: str = "INFO"):
        def _update():
            timestamp = datetime.now().strftime('%H:%M:%S')
            full_message = f"[{timestamp}] {level}: {message}\n"
            self.log_textbox.configure(state="normal")
            self.log_textbox.insert("end", full_message)
            self.log_textbox.see("end")
            self.log_textbox.configure(state="disabled")
        self.after(0, _update)

    def update_progress(self, message: str, value: float):
        def _update():
            self.progress_label.configure(text=message)
            self.progress_bar.set(value)
        self.after(0, _update)

    def create_portable_app(self):
        input_file = self.input_file_entry.get()
        output_dir = self.output_dir_entry.get()
        app_name = self.app_name_entry.get()
        
        if not input_file or not os.path.exists(input_file):
            messagebox.showerror("Error", "Please select a valid input file.")
            return
        if not output_dir or not app_name:
            messagebox.showerror("Error", "Please provide an app name and output directory.")
            return
        
        self.create_button.configure(state="disabled")
        self.log_textbox.configure(state="normal")
        self.log_textbox.delete("1.0", "end")
        self.log_textbox.configure(state="disabled")
        
        self.log_message("Starting portable app creation process...")
        
        thread = threading.Thread(
            target=self._create_portable_app_thread,
            args=(input_file, output_dir, app_name),
            daemon=True
        )
        thread.start()

    def _create_portable_app_thread(self, input_file, output_dir, app_name):
        extraction_engine = None
        try:
            self.update_progress("Starting process...", 0)
            
            is_installer, installer_type = FileAnalyzer.detect_installer_type(input_file)
            self.log_message(f"Detected Type: {installer_type}")
            
            source_path = input_file
            is_standalone = not is_installer

            if is_installer:
                self.log_message("Installer detected, attempting extraction...")
                extraction_engine = ExtractionEngine(self.config)
                
                def extraction_callback(message, value):
                    self.update_progress(message, value * 0.5)

                extracted_path = extraction_engine.extract_installer(input_file, extraction_callback)
                
                if extracted_path:
                    self.log_message(f"Extraction successful. Files at: {extracted_path}")
                    source_path = extracted_path
                    is_standalone = False
                else:
                    self.log_message("Extraction failed. Treating as a standalone executable.", "WARN")
                    self.update_progress("Extraction Failed", 0.5)
                    is_standalone = True
            
            self.log_message("Building portable application structure...")
            app_builder = PortableAppBuilder(self.config)
            
            def build_callback(message, value):
                self.update_progress(message, 0.5 + (value * 0.5))

            final_path = app_builder.build_portable_app(
                source_path=source_path,
                output_dir=output_dir,
                app_name=app_name,
                is_standalone=is_standalone,
                progress_callback=build_callback
            )
            self.log_message(f"Successfully created portable app at: {final_path}", "SUCCESS")
            self.update_progress("Completed!", 1.0)
            messagebox.showinfo("Success", f"Portable application created successfully!\n\nLocation: {final_path}")

        except Exception as e:
            logger.error(f"Fatal error during portable app creation: {str(e)}", exc_info=True)
            self.log_message(f"Error: {str(e)}", "ERROR")
            self.update_progress("Error!", 0)
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

        finally:
            self.after(0, lambda: self.create_button.configure(state="normal"))
            if extraction_engine:
                extraction_engine.cleanup()
                
    def check_dependencies(self):
        """Check for external dependencies and warn user if missing."""
        missing = []
        if not find_7zip():
            missing.append("7-Zip (7z.exe)")
        if not find_innoextract():
            missing.append("innoextract")
            
        if missing:
            msg = "The following dependencies were not found in your system's PATH or common locations:\n\n"
            msg += "\n".join(f"- {dep}" for dep in missing)
            msg += "\n\nSome extraction features may not work correctly. Please install them and ensure they are in your system's PATH."
            messagebox.showwarning("Dependencies Missing", msg)


if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    
    app = PortableXE_GUI()
    app.mainloop()
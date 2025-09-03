#!/bin/bash

echo "🔧 Installing required system tools..."

# Update system
sudo apt update && sudo apt upgrade -y

# Install apktool
sudo apt install -y apktool

# Install Metasploit (msfvenom)
if ! command -v msfvenom &> /dev/null; then
    echo "Installing Metasploit..."
    curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfinstall | sudo bash
fi

# Install Java and jarsigner
sudo apt install -y default-jdk

# Install zipalign (part of Android SDK Build-tools)
if ! command -v zipalign &> /dev/null; then
    echo "Please install Android SDK Build-tools manually to get zipalign."
fi

# Install baksmali
if ! command -v baksmali &> /dev/null; then
    echo "Installing baksmali..."
    sudo apt install -y baksmali
fi

echo "✅ All basic tools are installed. You're ready to use Egyrat!"

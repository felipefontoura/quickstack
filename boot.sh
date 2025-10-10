#!/bin/bash

set -euo pipefail

banner='
 ██████╗ ██╗   ██╗██╗ ██████╗██╗  ██╗███████╗████████╗ █████╗  ██████╗██╗  ██╗
██╔═══██╗██║   ██║██║██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
██║   ██║██║   ██║██║██║     █████╔╝ ███████╗   ██║   ███████║██║     █████╔╝ 
██║▄▄ ██║██║   ██║██║██║     ██╔═██╗ ╚════██║   ██║   ██╔══██║██║     ██╔═██╗ 
╚██████╔╝╚██████╔╝██║╚██████╗██║  ██╗███████║   ██║   ██║  ██║╚██████╗██║  ██╗
 ╚══▀▀═╝  ╚═════╝ ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝

'

echo -e "$banner"
echo "=> QuickStack is for fresh Ubuntu Server 24.04 installations only!"
echo -e "\nBegin installation (or abort with ctrl+c)..."

sudo apt-get update >/dev/null
sudo apt-get install -y git >/dev/null

echo "Cloning QuickStack..."
rm -rf ~/.local/share/quickstack
git clone https://github.com/felipefontoura/quickstack.git ~/.local/share/quickstack >/dev/null

QUICKSTACK_REF=${QUICKSTACK_REF:-"stable"}

if [[ $QUICKSTACK_REF != "main" ]]; then
  cd ~/.local/share/quickstack
  git fetch origin "$QUICKSTACK_REF" && git checkout "$QUICKSTACK_REF"
  cd - >/dev/null
fi

echo "Installation starting..."
source ~/.local/share/quickstack/install.sh

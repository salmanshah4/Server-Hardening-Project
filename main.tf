terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "main" {
  name     = "rg-lab-hardening-${var.yourname}"
  location = var.location
}

resource "azurerm_virtual_network" "main" {
  name                = "vnet-hardening-${var.yourname}"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name
  address_space       = ["10.30.0.0/16"]
}

resource "azurerm_subnet" "main" {
  name                 = "hardening-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.30.1.0/24"]
}

# NSG — allow SSH (Linux) and RDP (Windows) only
resource "azurerm_network_security_group" "main" {
  name                = "nsg-hardening-${var.yourname}"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "allow-ssh"
    priority                   = 1000
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-rdp"
    priority                   = 1010
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# Attach the NSG to the subnet so its rules actually apply to both VMs
resource "azurerm_subnet_network_security_group_association" "main" {
  subnet_id                 = azurerm_subnet.main.id
  network_security_group_id = azurerm_network_security_group.main.id
}

# ── Linux VM (Ubuntu 22.04) ───────────────────────────────────
# custom_data applies initial CIS hardening on first boot
resource "azurerm_network_interface" "linux" {
  name                = "nic-linux-${var.yourname}"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.main.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.linux.id
  }
}

resource "azurerm_public_ip" "linux" {
  name                = "pip-linux-${var.yourname}"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_linux_virtual_machine" "main" {
  name                            = "vm-linux-${var.yourname}"
  location                        = var.location
  resource_group_name             = azurerm_resource_group.main.name
  size = "Standard_D2ds_v4"
  admin_username                  = var.admin_username
  admin_password                  = var.admin_password
  disable_password_authentication = false
  network_interface_ids           = [azurerm_network_interface.linux.id]
  identity {
    type = "SystemAssigned"
  }
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

   source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"   # line 110 — was "0001-com-ubuntu-server-jammy"
    sku       = "server"             # line 111 — was "22_04-lts-gen2"
    version   = "latest"
  }

  # Initial CIS Level 1 hardening on first boot
  custom_data = base64encode(<<-EOF
    #!/bin/bash
    # CIS 1.1.1 — Disable unused filesystems
    echo "install cramfs /bin/true" >> /etc/modprobe.d/disable-fs.conf
    echo "install freevxfs /bin/true" >> /etc/modprobe.d/disable-fs.conf
    # CIS 2.2 — Disable unused services
    systemctl disable avahi-daemon 2>/dev/null || true
    systemctl disable cups 2>/dev/null || true
    # CIS 4.1 — Enable auditd
    apt-get update -y && apt-get install -y auditd
    systemctl enable auditd && systemctl start auditd
    # CIS 5.2 — SSH hardening
    sed -i "s/^#PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config
    sed -i "s/^#Protocol.*/Protocol 2/" /etc/ssh/sshd_config
    echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
    echo "ClientAliveCountMax 0"  >> /etc/ssh/sshd_config
    systemctl restart ssh
    # CIS 6.1 — Password policy via PAM
    apt-get install -y libpam-pwquality
    echo "minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1" \
      >> /etc/security/pwquality.conf
    # CIS 6.2 — Account lockout
    echo "auth required pam_faillock.so preauth silent deny=5 unlock_time=900" \
      >> /etc/pam.d/common-auth
    # Enable UFW firewall
    ufw --force enable
    ufw default deny incoming
    ufw allow 22/tcp
    echo "Hardening complete" >> /var/log/hardening.log
  EOF
  )
}
  resource "azurerm_virtual_machine_extension" "guestconfig_linux" {
  name                       = "AzurePolicyforLinux"
  virtual_machine_id         = azurerm_linux_virtual_machine.main.id
  publisher                  = "Microsoft.GuestConfiguration"
  type                       = "ConfigurationForLinux"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
}


# ── Windows VM ───────────────────────────────────────────────
resource "azurerm_network_interface" "windows" {
  name                = "nic-win-${var.yourname}"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.main.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.windows.id
  }
}

resource "azurerm_public_ip" "windows" {
  name                = "pip-win-${var.yourname}"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_windows_virtual_machine" "main" {
  name                  = "vm-win-${var.yourname}"
  computer_name         = "vm-win-lab" # Windows hostnames max out at 15 characters
  location              = var.location
  resource_group_name   = azurerm_resource_group.main.name
  size = "Standard_D2ds_v4"
  admin_username        = var.admin_username
  admin_password        = var.admin_password
  network_interface_ids = [azurerm_network_interface.windows.id]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-Datacenter"
    version   = "latest"
  }
}

output "linux_public_ip" {
  value = azurerm_public_ip.linux.ip_address
}

output "windows_public_ip" {
  value = azurerm_public_ip.windows.ip_address
}
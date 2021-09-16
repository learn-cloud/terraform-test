

# ================================= Variables ===================================

variable "region" {
  type        = string
  default     = "us-east"
}

variable "bastion_image" {
  description = "Specify Image to be used with Bastion VSI"
  type        = string
  default     = "r014-ce5f692d-763d-4b5a-bca2-93d6990fb3fd"
}

variable "prefix" {
  type        = string
  default     = "anand-cen8-"
}

variable "bastion_os_flavour" {
  type        = string
  default     = "linux"
}

variable "resource_group_id" {
  type        = string
  default  = "aadb17b59af948699a4b2bc66c1cda5c"
}

variable "api_key" {
  type        = string
  default  = "LFo12OeAQ5SI-9RdrdCN8QAfwajVR4xM4pojioI_ZtWg"
}

variable "bastion_ip_count" {
  description = "IP count is the total number of total_ipv4_address_count for Bastion Subnet"
  type        = number
  default     = 8
}

variable "zones" {
  description = "Region and zones mapping"
  type        = map(any)
  default = {
    "us-south" = ["us-south-1"]
    "us-east"  = ["us-east-1", "us-east-2", "us-east-3"]
    "eu-gb"    = ["eu-gb-1", "eu-gb-2", "eu-gb-3"]
    "eu-de"    = ["eu-de-1", "eu-de-2", "eu-de-3"]
    "jp-tok"   = ["jp-tok-1", "jp-tok-2", "jp-tok-3"]
    "au-syd"   = ["au-syd-1"]
  }
}


data "ibm_is_ssh_key" "ssh_key_id" {
  name = "anand-mac-key"
}

variable "user_ip_address" {
  type        = string
  default     = "106.51.105.102"
}

variable "bastion_profile" {
  description = "Specify the profile needed for Bastion VSI"
  type        = string
  default     = "bx2d-2x8"
}

# variable "public_gateway_ids" {
#   description = "List of ids of all the public gateways where subnets will get attached"
#   type        = list(any)
# }

# ======================= VPC ===================


resource "ibm_is_vpc" "vpc" {
  name           = "${var.prefix}vpc"
  resource_group = var.resource_group_id
}

resource "ibm_is_subnet" "bastion_sub" {
  name                     = "${var.prefix}subnet"
  vpc                      = ibm_is_vpc.vpc.id
  zone                     = element(var.zones[var.region], 0)
  total_ipv4_address_count = var.bastion_ip_count
  resource_group           = var.resource_group_id
  public_gateway           = ibm_is_public_gateway.pg.*.id[0]
}

resource "ibm_is_public_gateway" "pg" {
  count          = length(var.zones[var.region])
  name           = "${var.prefix}pg-${count.index + 1}"
  vpc            = ibm_is_vpc.vpc.id
  zone           = element(var.zones[var.region], 0)
  resource_group = var.resource_group_id
}

# output "pg_ids" {
#   value = ibm_is_public_gateway.pg.*.id
# }

# ====================================== SG ==========================================================
locals {
  sg_port = lower(var.bastion_os_flavour) == "windows" ? "3389" : "22"

  win_userdata = <<-EOUD
        Content-Type: text/x-shellscript; charset="us-ascii"
        MIME-Version: 1.0
        #ps1_sysnative
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri https://github.com/PowerShell/Win32-OpenSSH/releases/download/V8.6.0.0p1-Beta/OpenSSH-Win64.zip -OutFile "C:\Users\Administrator\OpenSSH-Win64.zip"      
        Expand-Archive -Path "C:\Users\Administrator\OpenSSH-Win64.zip" -DestinationPath "C:\Users\Administrator"
        Start-Process powershell.exe -Verb RunAs
        Copy-Item -Path "C:\Users\Administrator\OpenSSH-Win64" -Destination "C:\Program Files" -Force -Recurse -Verbose
        & 'C:\Program Files\OpenSSH-Win64\install-sshd.ps1'
        Start-Service sshd
        Set-Service -Name sshd -StartupType 'Automatic'
        New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
        Start-Sleep -s 20
        EOUD

  lin_userdata = <<-EOUD
        #!/bin/bash
        set -x
        ip_add=`hostname -I`
        os_flavour=$(lsb_release -a | grep "Distributor ID" | awk '{print $3}')
        if [ "$?" -eq "0" ]; then
            if [ "$os_flavour" = "Ubuntu" ] || [ "$os_flavour" = "Debian" ]; then
                echo "The OS flavour is $os_flavour"
                sudo apt-get update && sudo apt-get upgrade -y && sudo apt-get install nginx -y && sudo systemctl restart nginx && sudo systemctl enable nginx
                echo "Nginx Installation completed"
                sed -i "s/nginx/nginx App Server-IP: $ip_add/" /var/www/html/index.nginx-debian.html
            fi
        else
            echo "We are not going to install the Nginx on this OS."
        fi
        os_flavour2=$(cat /etc/os-release  | awk 'FNR == 3 {print $1}'| cut -d "=" -f 2 | tr -d '"')
        if [ "$?" -eq "0" ]; then
            if [ "$os_flavour2" = "centos" ]; then
                echo "The OS flavour is $os_flavour2"
                sudo yum install epel-release -y && sudo yum install nginx -y && sudo /bin/yum install firewalld -y && sudo firewall-cmd --permanent --add-service=http  && sudo firewall-cmd --reload && sudo systemctl enable nginx && sudo service nginx restart
            elif [ "$os_flavour2" = "rhel" ];then
                echo "The OS flavour is $os_flavour2"
                sudo yum install nginx -y && sudo /bin/yum install firewalld -y && sudo /bin/firewall-offline-cmd --add-port=80/tcp && sudo /bin/systemctl enable firewalld 
                sudo systemctl enable nginx && sudo service nginx restart
                echo "Nginx Installation completed"
                sudo /bin/systemctl restart firewalld
            else
                echo "We are not going to install the Nginx on this OS."
            fi
        fi
        EOUD
}

/**
* Security Group for Bastion Server
* Defining resource "Security Group". This will be responsible to handle security for the 
* Bastion Server
**/

resource "ibm_is_security_group" "bastion" {
  name           = "${var.prefix}bastion-sg"
  vpc            = ibm_is_vpc.vpc.id
  resource_group = var.resource_group_id
}


/**
* Security Group Rule for Bastion Server
* This inbound rule will allow the user to ssh connect to the Bastion server on port 22 from their local machine.
* This rule will only whitelist/allow the user's public IP address. So that no other person can access the bastion server.
**/

resource "ibm_is_security_group_rule" "bastion_rule_22" {
  group     = ibm_is_security_group.bastion.id
  direction = "inbound"
  remote    = var.user_ip_address
  tcp {
    port_min = local.sg_port
    port_max = local.sg_port
  }
}

resource "ibm_is_security_group_rule" "app_rule_80" {
  group     = ibm_is_security_group.bastion.id
  direction = "inbound"
  remote    = "0.0.0.0/0"
  tcp {
    port_min = "80"
    port_max = "80"
  }
}

resource "ibm_is_security_group_rule" "app_rule_22" {
  group     = ibm_is_security_group.bastion.id
  direction = "inbound"
  remote    = "0.0.0.0/0"
  tcp {
    port_min = "22"
    port_max = "22"
  }
}

/**
* Security Group Rule for Bastion Server
* This will allow all the outbound traffic from the Bastion server. Inbound traffics are restricted though, as specified in above rule.
**/

resource "ibm_is_security_group_rule" "bastion_outbound" {
  group     = ibm_is_security_group.bastion.id
  direction = "outbound"
  remote    = "0.0.0.0/0"
}


# ====================================  VSI ==================================

resource "ibm_is_instance" "bastion" {
  name           = "${var.prefix}bastion-vsi"
  keys           = [data.ibm_is_ssh_key.ssh_key_id.id]
  image          = var.bastion_image
  profile        = var.bastion_profile
  resource_group = var.resource_group_id
  vpc            = ibm_is_vpc.vpc.id
  zone           = element(var.zones[var.region], 0)
  # user_data      = lower(var.bastion_os_flavour) == "windows" ? local.win_userdata : local.lin_userdata

  primary_network_interface {
    subnet          = ibm_is_subnet.bastion_sub.id
    security_groups = [ibm_is_security_group.bastion.id]
  }
  lifecycle {
    prevent_destroy = false // TODO: Need to toggle this variable before publishing the script.
    ignore_changes = [
      user_data,
    ]
  }
}

/**
* Floating IP address for Bastion Server or Jump Server. This is the static public IP attached to the bastion server. User will use this floating IP to ssh connect to the 
* bastion server from their local machine.
* Element : Floating IP
* This resource will be used to attach a floating IP address.
**/
resource "ibm_is_floating_ip" "bastion_floating_ip" {
  name           = "${var.prefix}bastion-fip"
  resource_group = var.resource_group_id
  target         = ibm_is_instance.bastion.primary_network_interface.0.id
  depends_on     = [ibm_is_instance.bastion]
}


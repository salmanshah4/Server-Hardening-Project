variable "yourname" {
  description = "Short name used to make resource names unique (lowercase, no spaces)"
  type        = string
}

variable "location" {
  description = "Azure region to deploy into"
  type        = string
  default     = "eastus"
}

variable "admin_username" {
  description = "Admin username for both VMs"
  type        = string
  default     = "azureadmin"
}

variable "admin_password" {
  description = "Admin password for both VMs"
  type        = string
  sensitive   = true
}

# Init-Unlock

Init-unlock is designed to be a small binary running at early init from the ramdisk to provide key materiel to decrypt the OS drive.

The first objective of this project is to acquire key materiel from HashiCorp's Vault using hardware attributes as accessor values.
This will permit MaaS to:
1. Use host hardware information acquired during comissioning to write the OS volume keyfile into the vault during deployment
2. Build the binary into the initramfs with a pre-decrypt hook to execute it
3. Configure the kernel commandline with the HTTP client parameters for connecting to the appropriate vault during init

Subsequent efforts will focus on extracting the key from TPM directly or using TPM values to pull it from Vault or another source.